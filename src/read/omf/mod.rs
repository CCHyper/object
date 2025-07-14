//! Intel OMF reader (supports 16-bit and 32-bit records)

mod consts;
mod section;
mod symbol;

use consts::*;
use section::{OmfSection, OmfRelocation};
use symbol::OmfSymbol;

use crate::read::{
    self, Architecture, Error, ObjectSection, ObjectSectionIndex, ObjectSymbol,
    ObjectSymbolTable, ReadRef, RelocationKind, RelocationEncoding, Result, SectionFlags,
    SectionIndex, SymbolFlags, SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

/// A segment group defined by `GRPDEF`.
#[derive(Debug)]
pub struct OmfGroup<'data> {
    pub name: &'data str,
    pub seg_indices: Vec<u8>,
}

/// A COMDAT or COMDEF (minimal fields for now).
#[derive(Debug)]
// === COMDAT: Common Data records for duplicate-linkable functions/data ===
pub struct OmfComdat<'data> {
    pub name: &'data str,
    pub selection: u8,
    pub segment_index: u8,
    pub offset: u32,
    pub segment_name: Option<&'data str>,
    pub data: Option<&'data [u8]>,
}

/// Common (uninitialized) symbol defined by a COMDEF record.
#[derive(Debug)]
// === COMDEF: Common (uninitialized) data symbols, like BSS ===
pub struct OmfCommon<'data> {
    pub name:        &'data str,
    pub elem_size:   u32,   // size of one element
    pub elem_count:  u32,   // number of elements
    pub is_far:      bool,  // far vs. near
    pub is_32bit:    bool,  // width of size/count fields
}

/// Parsed Intel OMF object file.
#[derive(Debug)]
// === Main object container for parsed OMF file data ===
pub struct OmfFile<'data, R: ReadRef<'data>> {
    pub data: R,
    pub module_name: Option<&'data str>,
    pub lnames: Vec<&'data str>,
    pub segments: Vec<OmfSegment<'data>>,
    pub symbols: Vec<OmfSymbol<'data>>,
    pub groups:  Vec<OmfGroup<'data>>,
    pub comdats: Vec<OmfComdat<'data>>,
    pub commons: Vec<OmfCommon<'data>>,
}

/// Internal segment helper.
#[derive(Debug)]
struct OmfSegment<'data> {
    pub name: &'data str,
    pub data: &'data [u8],
    pub flags: SectionFlags,
    pub fixups: Vec<OmfRelocation>,
}

// === Implementation block for OmfFile: parsing, section access, etc. ===
impl<'data, R: ReadRef<'data>> OmfFile<'data, R> {
    /// Quick sniff (0x80-0x9F record id range).
    pub fn peek(data: R) -> core::result::Result<(), ()> {
        if let Some(&b) = data.read_bytes_at(0, 1).ok().and_then(|s| s.first()) {
            return if (0x80..=0x9F).contains(&b) { Ok(()) } else { Err(()) };
        }
        Err(())
    }

    /// Full parse.
    pub fn parse(data: R) -> Result<Self> {
        let bytes = data.read_bytes_at(0, data.len() as u64)?.as_ref();

        let mut pos = 0;
        let mut lnames = Vec::new();
        let mut segments = Vec::new();
        let mut symbols  = Vec::new();
        let mut groups   = Vec::new();
        let mut comdats  = Vec::new();
        let mut commons  = Vec::new();
        let mut module_name = None;

        while pos + 3 <= bytes.len() {
            let rec = bytes[pos];
            let len = u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
            let body = &bytes[pos + 3 .. pos + 3 + len];
            pos += 3 + len;

            // Parse OMF record types: identify based on type byte (rec)
            match rec {

                // THEADR (Translator Header): Marks the start of a new module or source file.
                // Typically contains the original source file name, used mostly for diagnostics.
                // Only one THEADR is expected per object file.
                THEADR => {
                    module_name = Some(read::parse_string(body)?);
                }

                // LNAMES (Logical Names): String table for segment/class/group identifiers.
                // These are 1-based indexes used in SEGDEF, GRPDEF, COMDAT, etc.
                // Contents may include segment names like 'CODE', 'DATA', 'CONST'.
                LNAMES => {
                    let mut p = 0;
                    while p < body.len() {
                        let s = read::parse_string(&body[p..])?;
                        lnames.push(s);
                        p += 1 + s.len();
                    }
                }

                // SEGDEF / SEGDEF32: Segment Definition records (16-bit and 32-bit).
                // Define a memory segment's name, class, alignment, size, and combine type.
                // Paired with LEDATA records that supply the raw bytes.
                // Segment index (1-based) is used by PUBDEF, COMDAT, FIXUPP, etc.
                // SEGDEF32 adds support for 32-bit offsets and lengths.
                SEGDEF | SEGDEF32 => {
                    let attr = body[0];
                    let is_code  = attr & 0x01 == 0;
                    let is_32bit = rec & 1 == 1;

                    let (seg_len, name_idx) = if is_32bit {
                        let len = u32::from_le_bytes([body[1], body[2], body[3], body[4]]) as usize;
                        (len, body[5] as usize)
                    } else {
                        let len = u16::from_le_bytes([body[1], body[2]]) as usize;
                        (len, body[3] as usize)
                    };

                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    let flags = if is_code { SectionFlags::EXECUTABLE } else { SectionFlags::NONE };
                    segments.push(OmfSegment { name, data: &[], flags, fixups: Vec::new() });

                    // LEDATA will fill `data` later.
                }

                // LEDATA: Raw data contents for a segment defined earlier by SEGDEF.
                LEDATA | LLEDATA => {
                    if let Some(seg) = segments.last_mut() {
                        seg.data = body;
                    }
                }

                // PUBDEF: Public symbol declaration (named address within segment).
                PUBDEF | LPUBDEF => {
                    let mut p = 0;
                    while p < body.len() {
                        let name = read::parse_string(&body[p..])?;
                        p += 1 + name.len();
                        let offset = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
                        let seg  = body[p + 2]; p += 3;
                        symbols.push(OmfSymbol::new_public(name, seg, offset));
                    }
                }

                // EXTDEF: External symbol reference (import).
                EXTDEF | LEXTDEF => {
                    let mut p = 0;
                    while p < body.len() {
                        let name = read::parse_string(&body[p..])?;
                        p += 1 + name.len();
                        symbols.push(OmfSymbol::new_undefined(name));
                    }
                }

                // FIXUPP: Contains relocation (fixup) records that patch addresses at link time.
                // Each entry specifies a location in LEDATA or COMDAT that must be adjusted.
                // Fixups may refer to segments, groups, or external symbols.
                // This parser currently does not resolve or apply these fixups — placeholder only.
                FIXUPP => {
                    
                    // This implementation currently skips "thread" subrecords (subtype 0b10),
                    // which are used to compress FIXUPP data by setting reusable frame/target values.
                    // Only explicit fixup records are parsed for now.
                    //
                    // TODO: Add support for thread definitions (THREAD subrecords) when needed.
                    
                    // Parse only explicit segment-relative FIXUP subrecords.
                    let mut p = 0;
                    while p < body.len() {
                        let typ = body[p]; p += 1;

                        // If high bit = 0b10, this is a THREAD sub-record → skip (see comment above).
                        if typ & 0x80 == 0 { continue; }   // thread, ignored

                        // --- decode location ---
                        let loc_size = match (typ >> 5) & 0b11 {
                            0b00 => 8,   // 8-bit offset    (rare)
                            0b01 => 16,  // 16-bit offset   (near)
                            0b10 => 32,  // 32-bit offset   (far/32)
                            _    => 16,
                        };
                        let loc_off = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
                        p += 2;

                        // --- decode target ---
                        let tgt = body[p]; p += 1;
                        let target_seg = tgt; // segment index (1-based)

                        // Skip disp/extra bytes if present (not used yet).
                        if (typ & 0x04) != 0 { p += 1; } // 1-byte displacement

                        // Attach relocation to most recent segment.
                        if let Some(seg) = segments.last_mut() {
                            seg.fixups.push(OmfRelocation {
                                offset:   loc_off,
                                target_segment: target_seg as u16,
                                kind:     RelocationKind::Absolute,
                                encoding: RelocationEncoding::Generic,
                                size:     loc_size as u8,
                                addend:   0,
                            });
                        }
                    }
                }

                // GRPDEF: Group Definition — logical group of multiple SEGDEFs (e.g., DGROUP).
                // Common in 16-bit OMF: allows far pointers or grouped data access.
                // Groups are referenced in FIXUPP and other relocatable records.
                // Currently decoded into group name + list of segment indexes.
                GRPDEF => {
                    let mut p = 0;
                    let name_idx = body[p] as usize; p += 1;
                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    let count = body[p] as usize; p += 1;
                    let seg_indices = body[p .. p + count].to_vec();
                    groups.push(OmfGroup { name, seg_indices });
                }

                // COMDEF: Common (BSS-style) uninitialized symbols. Size only.
                COMDEF => {
                    // COMDEF record format (16- & 32-bit):
                    // [name_index] [type] [elem_size] [elem_count]
                    //  1 byte       1     2/4         2/4
                    // Type 0x00 = near, 0x02 = far. We ignore arrays-of-commons for now
                    // beyond elem_count > 1.
                    let mut p = 0;
                    let name_idx = body[p] as usize; p += 1;
                    let typ = body[p]; p += 1;
                    let is_far = typ & 0x02 != 0;
                    let is_32bit = (rec & 1) == 1;

                    let read_u = |bytes: &[u8], off: &mut usize, w32: bool| -> u32 {
                        if w32 {
                            let v = u32::from_le_bytes([bytes[*off], bytes[*off+1], bytes[*off+2], bytes[*off+3]]);
                            *off += 4; v
                        } else {
                            let v = u16::from_le_bytes([bytes[*off], bytes[*off+1]]) as u32;
                            *off += 2; v
                        }
                    };

                    let elem_size  = read_u(body, &mut p, is_32bit);
                    let elem_count = read_u(body, &mut p, is_32bit);

                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    commons.push(OmfCommon {
                        name,
                        elem_size,
                        elem_count,
                        is_far,
                        is_32bit,
                    });

                    // NOTE: Borland & Watcom emit extended COMDEF variants (8087, flex-array)
                    // which include additional alignment or class bytes. These are not yet parsed.
                }

                // COMDAT: Deduplicated, selectable data/code fragment.
                COMDAT => {
                    // NOTE: Retain all COMDATs (selection logic deferred).
                    // Some Borland/Watcom variants define segment implicitly inside COMDAT;
                    // if segment_index doesn't map to an existing SEGDEF, we fallback.
                    let is_32bit = (rec & 1) == 1;
                    let mut p = 0;

                    if body.len() < 3 {
                        continue; // too short to be valid
                    }

                    let selection = body[p]; p += 1;
                    let mut attr_or_name = body[p]; p += 1;

                    let (attributes, name_idx) = if attr_or_name >= 0xF0 {
                        // Likely a known attribute; use it
                        let attributes = attr_or_name;
                        let name_idx = body[p]; p += 1;
                        (attributes, name_idx as usize)
                    } else {
                        // No attribute byte; fallback
                        (0, attr_or_name as usize)
                    };

                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");

                    let segment_index = body.get(p).copied().unwrap_or(0); p += 1;

                    let offset = if is_32bit {
                        u32::from_le_bytes([
                            *body.get(p).unwrap_or(&0),
                            *body.get(p + 1).unwrap_or(&0),
                            *body.get(p + 2).unwrap_or(&0),
                            *body.get(p + 3).unwrap_or(&0),
                        ])
                    } else {
                        u16::from_le_bytes([
                            *body.get(p).unwrap_or(&0),
                            *body.get(p + 1).unwrap_or(&0),
                        ]) as u32
                    };
                    let seg_idx = segment_index.saturating_sub(1) as usize;
                    let (segment_name, data) = if let Some(seg) = segments.get(seg_idx) {
                        (Some(seg.name), Some(seg.data))
                    } else {
                        // TODO: Borland/Watcom-specific variation may embed data or attributes not currently parsed.
                        // TODO: Borland/Watcom-style implicit data:
                        // Some OMF toolchains (e.g., Watcom/Borland) may define a COMDAT with no SEGDEF/LEDATA,
                        // embedding the section data directly inside the COMDAT record. These are effectively
                        // self-contained 'mini-sections' that should be parsed and stored here.
                        // For now, we detect this by absence of a matching SEGDEF and placeholder detection:
                        let looks_like_inline_data = body.len() > p + 2; // crude check (TODO: refine format-based)
                        (None, None)
                    };
                    comdats.push(OmfComdat {
                        name,
                        selection,
                        segment_index,
                        offset,
                        segment_name,
                        data,
                    });
                }
                    let selection = body[p]; p += 1;
                    let mut attr_or_name = body[p]; p += 1;
                    let (attributes, name_idx) = if attr_or_name >= 0xF0 {
                        let attributes = attr_or_name;
                        let name_idx = body[p]; p += 1;
                        (attributes, name_idx as usize)
                    } else {
                        (0, attr_or_name as usize)
                    };
                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    let segment_index = body.get(p).copied().unwrap_or(0); p += 1;
                    let offset = if is_32bit {
                        u32::from_le_bytes([
                            *body.get(p).unwrap_or(&0),
                            *body.get(p + 1).unwrap_or(&0),
                            *body.get(p + 2).unwrap_or(&0),
                            *body.get(p + 3).unwrap_or(&0),
                        ])
                    } else {
                        u16::from_le_bytes([
                            *body.get(p).unwrap_or(&0),
                            *body.get(p + 1).unwrap_or(&0),
                        ]) as u32
                    };
                    comdats.push(OmfComdat {
                        name,
                        selection,
                        segment_index,
                        offset,
                    });
                }
                
                //
                // Ignored / not yet needed
                //
                
                // MODEND: Indicates the logical end of the object module.
                // Usually appears once, possibly with entry point info. Currently unused.
                MODEND => {}
                
                // MODEND32: 32-bit version of MODEND, typically for 386+ objects.
                // Entry point info and termination marker. Ignored for now.
                MODEND32 => {}
                
                // COMENT: COMMENT records embed optional metadata, such as compiler version,
                // copyright strings, or linker directives. This parser currently skips them.
                COMENT => {}
                
                // BAKPAT and NBKPAT: Used for back-patching fixups, often in very old tools.
                // Rarely encountered today. Skipped unless needed for legacy format support.
                BAKPAT => {}
                NBKPAT => {}
                
                // LIBHDR and LIBDIR: Records for import libraries or static archives.
                // They contain indexing metadata but not object code. Ignored here.
                LIBHDR => {}
                LIBDIR => {}
                
                // RIDATA: Repeated initialization data. Alternative to LEDATA.
                // Describes blocks of data filled with repeating values. Not parsed yet.
                RIDATA => {}

                // LIDATA and LLIDATA: Iterated data blocks.
                // Support compressed initialization of repeating structures.
                // Skipped here but required for full fidelity.
                LIDATA => {}
                LLIDATA => {}
                
                // LLEDATA: LEDATA variant for 32-bit segmented objects.
                // Provides raw segment data like LEDATA but uses extended addressing.
                // Not yet supported here.
                LLEDATA => {}
                
                // LCOMDEF: Extended COMDEF record used for common (BSS-style) uninitialized symbols.
                // Supports 32-bit or segmented addressing for large-model objects. Not yet implemented.
                LCOMDEF => {}
                
                // LSEGDEF: Extended SEGDEF record used to define segments with 32-bit sizes and attributes.
                // Equivalent to SEGDEF, but required for full 32-bit OMF support. Not yet implemented.
                LSEGDEF => {}
                
                // LGRPDEF: Extended GRPDEF for 32-bit group addressing.
                // Not implemented yet, pending FIXUPP compatibility.
                LGRPDEF => {}
                
                // LIDRNAME, LIDRTYP, LIDRVAL: Linker incremental debugging support.
                // These records carry symbolic debugging data (CV, DWARF, etc).
                // Not part of core object parsing and skipped here.
                LIDRNAME => {}
                LIDRTYP => {}
                LIDRVAL => {}

                _ => return Err(Error("unknown OMF record")),
            }
        }

        Ok(Self {
            data,
            module_name,
            lnames,
            segments,
            symbols,
            groups,
            comdats,
            commons,
        })
    }

    /// Turn parsed segments into `OmfSection` iterators.
    pub fn sections(&'data self) -> impl Iterator<Item = OmfSection<'data>> + '_ {
        self.segments.iter().enumerate().map(|(idx, seg)| OmfSection {
            index: idx,
            name: seg.name,
            data: seg.data,
            flags: seg.flags,
            relocs: seg.fixups.clone(),
        })
        // COMDAT sections: we expose all COMDAT records, even if duplicates exist.
        // The `selection` field in each COMDAT record determines how linkers resolve duplicates:
        //   0x00 = PickAny, 0x01 = PickSame, 0x02 = PickSameSize, 0x03 = NoDuplicates, etc.
        // We do not enforce these selection rules in this parser — all COMDATs are returned.
        // If future deduplication is needed, filtering based on `selection` can be added here.
        for comdat in &self.comdats {
            let name = comdat.name;
            let data = comdat.data.unwrap_or(&[]);
            let section = OmfSection {
                name,
                data,
                relocs: Vec::new(),
                flags: SectionFlags::COMDAT,
            };
            sections.push(section);
        }
        // NOTE: If `data` is empty, it likely comes from a COMDAT that defines no segment
        // or was emitted by a Borland/Watcom-style object. This still gets exposed for introspection.
    }
}

/* ---------- Trait implementations ---------- */

impl<'data, R: ReadRef<'data>> ObjectSymbolTable<'data> for OmfFile<'data, R> {
    type Symbol = OmfSymbol<'data>;

    fn symbols(&self) -> Box<dyn Iterator<Item = Self::Symbol> + '_> {
        Box::new(self.symbols.iter().cloned())
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        self.symbols.get(index.0).cloned().ok_or(Error("invalid OMF symbol index"))
    }
}
