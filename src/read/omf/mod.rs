//! Intel OMF reader (supports 16-bit and 32-bit records)

mod consts;
mod section;
mod symbol;
mod object;

use consts::*;
use section::{OmfSection, OmfRelocation};
use symbol::OmfSymbol;

use crate::read::{
    self, Architecture, Error, ObjectSection, ObjectSectionIndex, ObjectSymbol,
    ObjectSymbolTable, ReadRef, RelocationKind, RelocationEncoding, Result, SectionFlags,
    SectionIndex, SymbolFlags, SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use self::comment::{OmfComment, OmfCommentKind};

use crate::read::omf::section::OmfSectionData;

/// Logical segment group defined via GRPDEF (e.g., DGROUP).
/// Stores a group name and 1-based indices of associated segments.
/// Used by some linkers to load multiple segments into the same register.
#[derive(Debug)]
struct OmfGroup<'data> {
    name: &'data str,
    segment_indices: Vec<u16>,
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

/// Helper: Determines if a comment class type supports subtyped comments.
fn is_known_subtyped_class(class: u8) -> bool {
    matches!(class, 0x00 | 0x01 | 0x9A) // Microsoft, Borland, Watcom
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
    pub groups: Vec<OmfGroup<'data>>,
    pub comdats: Vec<OmfComdat<'data>>,
    pub commons: Vec<OmfCommon<'data>>,
    pub comments: Vec<OmfComment<'data>>,
}

/// Internal segment helper.
#[derive(Debug)]
struct OmfSegment<'data> {
    pub name: &'data str,
    pub data: &'data [u8],
    pub flags: SectionFlags,
    pub fixups: Vec<OmfRelocation>,
}

/// Enumerates common OMF COMMENT classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmfCommentClass {
    /// Microsoft-specific comment (class = 0x00).
    Microsoft,

    /// Borland-specific comment (class = 0x01).
    Borland,

    /// Watcom-specific comment (class = 0x9A).
    Watcom,

    /// Embedded DWARF debug info (e.g., class = 0x88).
    Dwarf,

    /// Compiler version info.
    Version,

    /// Unknown or unclassified.
    Unknown(u8),
}

/// Represents a parsed COMMENT record from an OMF object.
#[derive(Debug)]
pub struct OmfComment<'data> {
    /// The comment class type (e.g., DWARF, copyright, version, etc.)
    pub class: OmfCommentClass,

    /// Subclass byte if applicable.
    pub subtype: Option<u8>,

    /// The raw payload (excluding class/subclass/type bytes).
    pub data: &'data [u8],

    /// Raw bytes including class/subtype for unknown/unparsed cases.
    pub raw: &'data [u8],
}

impl From<u8> for OmfCommentKind {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Self::Translator,
            0x88 => Self::MicrosoftVer,
            0x99 => Self::BorlandVer,
            0x9C => Self::WatcomVer,
            other => Self::Unknown(other),
        }
    }
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
        let mut comments = Vec::new();
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

                // PUBDEF: Defines a symbol (function, variable, etc.) that is visible to the linker.
                // Each entry specifies a name, segment index, and offset. These are considered
                // "defined" (global) symbols and should be emitted via the standard symbol iterator.
                PUBDEF => {
                    let mut p = 0;
                    while p + 2 < body.len() {
                        let name_idx = body[p] as usize; p += 1;
                        let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");

                        let seg_idx = body[p]; p += 1;
                        let offset = u16::from_le_bytes([body[p], body[p+1]]) as u64; p += 2;

                        symbols.push(OmfSymbol {
                            name,
                            segment: Some(seg_idx),
                            offset,
                            global: true,
                            is_comdat: false,
                        });
                    }
                }
                
                // LPUBDEF: 32-bit version of PUBDEF, with larger offsets and segment indices.
                // Defines global/public symbols, same as PUBDEF.
                LPUBDEF => {
                    let mut p = 0;
                    while p + 4 < body.len() {
                        let name_idx = body[p] as usize; p += 1;
                        let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");

                        let seg_idx = u16::from_le_bytes([body[p], body[p + 1]]); p += 2;
                        let offset = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]) as u64;
                        p += 4;

                        symbols.push(OmfSymbol {
                            name,
                            segment: Some(seg_idx as u8), // NOTE: OMF segment indices are typically u8, but LPUBDEF uses u16 — if more than 255 segments ever appear, we should update OmfSymbol to match.
                            offset,
                            global: true,
                            is_comdat: false,
                        });
                    }
                }

                // EXTDEF: Declares a symbol imported from another object or library.
                // These are marked undefined in the final object symbol table.
                EXTDEF | LEXTDEF => {
                    let mut p = 0;
                    while p < body.len() {
                        let name_idx = body[p] as usize; p += 1;
                        let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");

                        symbols.push(OmfSymbol {
                            name,
                            segment: None,
                            offset: 0,
                            global: true,
                            is_comdat: false,
                        });
                    }
                }
                
                // LEXTDEF: Extended EXTDEF used in 32-bit OMF files.
                // Declares undefined external symbols, just like EXTDEF.
                // Some toolchains (Watcom/Borland) include optional ordinal fields here.
                LEXTDEF => {
                    let mut p = 0;
                    while p + 1 < body.len() {
                        let name_idx = body[p] as usize; p += 1;

                        // If there's an ordinal field (Watcom/Borland may add it), skip 2 bytes.
                        let _maybe_ordinal = if p + 1 < body.len() {
                            let ord = u16::from_le_bytes([body[p], body[p + 1]]);
                            p += 2;
                            Some(ord)
                        } else {
                            None
                        };

                        let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");

                        symbols.push(OmfSymbol {
                            name,
                            segment: None,
                            offset: 0,
                            global: true,
                            is_comdat: false,
                        });
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
                                target:   OmfFixupTarget::Segment(target_seg as u16),
                                frame:    Some(OmfFixupFrame::Location), // Default to location-relative frame (FIXME: decode actual frame)
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
                    if body.is_empty() {
                        continue;
                    }

                    let group_name_index = body[0] as usize;
                    let mut segment_indices = Vec::new();

                    let mut i = 1;
                    while i < body.len() {
                        // OMF encodes each group entry as a pair: kind + index
                        let kind = body[i]; i += 1;
                        let index = body.get(i).copied().unwrap_or(0); i += 1;

                        if kind == 0x02 {
                            // 0x02 = segment index (1-based)
                            segment_indices.push(index as u16);
                        } else {
                            // TODO: Support other kinds (0x01 = group, 0x03 = external symbol)
                        }
                    }

                    if let Some(name) = lnames.get(group_name_index) {
                        groups.push(OmfGroup {
                            name,
                            segment_indices,
                        });
                    }

                    // TODO: These groups are recorded but not yet used for fixup resolution.
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

                // COMDAT: Defines a link-once section, usually function- or data-level granularity.
                // Format includes type (code/data), linkage attributes, and data body.
                // Also includes local fixups, which are handled separately.
                // This is common in Watcom, Borland, and Microsoft OMFs for inlined functions.
                //
                // Note: Borland/Watcom may omit explicit SEGDEF for COMDATs and treat COMDAT as implicit segment.
                //       We assume SEGDEF precedes and segment list is valid.
                //       COMDATs may be mergeable; we record them all for now.
                //
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
                    p += if is_32bit { 4 } else { 2 };

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
                        if looks_like_inline_data {
                            let data_body = &body[p..];

                            // Create a synthetic segment and attach it
                            segments.push(OmfSection {
                                index: segments.len(),
                                name,
                                data: OmfSectionData::Comdat {
                                    offset,
                                    data: data_body,
                                },
                                flags: SectionFlags::None,
                                relocs: vec![],
                            });

                            (Some(name), Some(OmfSectionData::Comdat {
                                offset,
                                data: data_body,
                            }))
                        } else {
                            (None, None)
                        }
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
                
                //
                // Ignored / not yet needed
                //
                
                // MODEND: Indicates the logical end of the object module.
                // Usually appears once, possibly with entry point info. Currently unused.
                MODEND => {}
                
                // MODEND32: 32-bit version of MODEND, typically for 386+ objects.
                // Entry point info and termination marker. Ignored for now.
                MODEND32 => {}
                
                // COMENT: Comment records embed optional metadata, such as compiler version,
                // copyright strings, or linker directives. This parser currently skips them.
                COMENT => {
                    if let Some(cmt) = comment::parse_comment(body) {
                        comments.push(cmt);
                    }
                }
                
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
                LIDATA | LLIDATA => {
                    if body.len() < 3 {
                        continue;
                    }
                    let offset = u16::from_le_bytes([body[0], body[1]]) as u32;
                    let raw = &body[2..];

                    if let Some(seg) = segments.last_mut() {
                        seg.data = OmfSectionData::Lidata { offset, raw };
                    }

                    // TODO: Implement recursive expansion of LIDATA when needed.
                }
                
                // LEDATA / LLEDATA:
                // Defines raw initialized data contents for a previously declared segment.
                // LEDATA is the standard form for 16-bit objects; LLEDATA is its 32-bit variant.
                // These records contain a segment index (referring to a SEGDEF), an offset
                // within that segment, and the actual byte data to emit.
                //
                // This data is usually followed by a FIXUPP record that patches addresses within
                // the payload, allowing segment-relative references to external symbols,
                // groups, or other segments.
                //
                // Multiple LEDATA records can refer to the same SEGDEF, each providing data at
                // different offsets within the segment's address space. In practice, segments
                // may be assembled from multiple LEDATA chunks. This is especially common in
                // Microsoft-format OMF.
                //
                // Watcom and Borland also emit LEDATA for most code/data blocks that are not
                // marked COMDAT.
                LEDATA | LLEDATA => {
                    let is_32bit = rec == LLIDATA;
                    let mut p = 0;

                    let seg_idx = body.get(p).copied().unwrap_or(0).saturating_sub(1) as usize;
                    p += 1;

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
                    p += if is_32bit { 4 } else { 2 };

                    let data_body = &body[p..];

                    if let Some(seg) = segments.get_mut(seg_idx) {
                        seg.data = OmfSectionData::Lidata {
                            offset,
                            encoded: data_body,
                        };
                    }
                }
                
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
            comments,
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

// --- Unimplemented record handlers ---
/// Parse LIDATA: Iterated data (patterned uninitialized storage)
/// Not yet implemented. Common in BSS-like space savings.
fn parse_lidata(_body: &[u8]) {
    // TODO: Parse repeat descriptors and recursively nested LIDATA
}

/// Parse LLIDATA: Extended iterated data with 32-bit offsets
/// Rare. Not yet implemented.
fn parse_llidata(_body: &[u8]) {
    // TODO: Support 32-bit range iterated initializations
}

/// Parse LCOMDEF: Extended COMDEF supporting 32-bit or segmented layout
/// Used in large model or segmented data. Placeholder only.
fn parse_lcomdef(_body: &[u8]) {
    // TODO: Implement parsing of extended common symbols
}

/// Parse LSEGDEF: Extended SEGDEF variant with larger fields
/// Required for full 32-bit OMF object parsing.
fn parse_lsegdef(_body: &[u8]) {
    // TODO: Handle extended segment definitions (larger offsets)
}

/// Parse LGRPDEF: Extended group definition record
/// Used in segmented models. Not yet implemented.
fn parse_lgrpdef(_body: &[u8]) {
    // TODO: Decode group associations
}

/// Parse LLEDATA: Large LEDATA variant with 32-bit addressing
/// Used in OMF32 for data sections exceeding 64KB.
fn parse_lleddata(_body: &[u8]) {
    // TODO: Implement handling of extended LEDATA
}

/// Parse BAKPAT: Backpatch record for old linkers
/// Rare. Not used in modern OMF workflows.
fn parse_bakpat(_body: &[u8]) {
    // TODO: Handle segment-relative backpatching (obsolete)
}

/// Parse NBKPAT: Named backpatch variant
/// Rare extension of BAKPAT using symbol names.
fn parse_nbkpat(_body: &[u8]) {
    // TODO: Consider handling named patching
}

/// Parse RIDATA: Possibly reserved or tool-specific record
/// Currently ignored.
fn parse_ridata(_body: &[u8]) {
    // TODO: Investigate usage in Watcom or Borland output
}

/// Parse LIDRNAME: Index record - symbol name
/// Used for linker index/debug information.
fn parse_lidrname(_body: &[u8]) {
    // TODO: Handle index-based symbol mapping
}

/// Parse LIDRTYP: Index record - type tag
/// Used for extended symbol typing.
fn parse_lidrtyp(_body: &[u8]) {
    // TODO: Possibly useful in DWARF-style index objects
}

/// Parse LIDRVAL: Index record - symbol value
/// Usually part of debug record grouping.
fn parse_lidrval(_body: &[u8]) {
    // TODO: Add support if .OBJ files rely on this
}

/// Parse LIBHDR: Marks start of a static library file (.LIB)
/// Used before LIBDIR records. No-op for object files.
fn parse_libhdr(_body: &[u8]) {
    // TODO: Parse LIB archive metadata (name, version)
}

/// Parse LIBDIR: Table of contents for .LIB archive
/// Required to resolve modules within libraries.
fn parse_libdir(_body: &[u8]) {
    // TODO: Build module/offset map for archive members
}
