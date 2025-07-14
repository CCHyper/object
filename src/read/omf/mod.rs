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
pub struct OmfComdat<'data> {
    pub name: &'data str,
    pub selection: u8,
    pub segment_index: u8,
    pub offset: u32,
}

/// Parsed Intel OMF object file.
#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data>> {
    pub data: R,
    pub module_name: Option<&'data str>,
    pub lnames: Vec<&'data str>,
    pub segments: Vec<OmfSegment<'data>>,
    pub symbols: Vec<OmfSymbol<'data>>,
    pub groups:  Vec<OmfGroup<'data>>,
    pub comdats: Vec<OmfComdat<'data>>,
}

/// Internal segment helper.
#[derive(Debug)]
struct OmfSegment<'data> {
    pub name: &'data str,
    pub data: &'data [u8],
    pub flags: SectionFlags,
    pub fixups: Vec<OmfRelocation>,
}

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
        let mut module_name = None;

        while pos + 3 <= bytes.len() {
            let rec = bytes[pos];
            let len = u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
            let body = &bytes[pos + 3 .. pos + 3 + len];
            pos += 3 + len;

            match rec {
                THEADR => {
                    module_name = Some(read::parse_string(body)?);
                }

                LNAMES => {
                    let mut p = 0;
                    while p < body.len() {
                        let s = read::parse_string(&body[p..])?;
                        lnames.push(s);
                        p += 1 + s.len();
                    }
                }

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

                LEDATA | LLEDATA => {
                    if let Some(seg) = segments.last_mut() {
                        seg.data = body;
                    }
                }

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

                EXTDEF | LEXTDEF => {
                    let mut p = 0;
                    while p < body.len() {
                        let name = read::parse_string(&body[p..])?;
                        p += 1 + name.len();
                        symbols.push(OmfSymbol::new_undefined(name));
                    }
                }

                FIXUPP => {
                    if let Some(seg) = segments.last_mut() {
                        seg.fixups.extend(OmfRelocation::parse_all(body));
                    }
                }

                GRPDEF => {
                    let mut p = 0;
                    let name_idx = body[p] as usize; p += 1;
                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    let count = body[p] as usize; p += 1;
                    let seg_indices = body[p .. p + count].to_vec();
                    groups.push(OmfGroup { name, seg_indices });
                }

                COMDEF => {
                    // Not yet materialised – placeholder for common symbols.
                }

                COMDAT => {
                    let selection = body[0];
                    let name_idx  = body[1] as usize;
                    let name = lnames.get(name_idx.saturating_sub(1)).copied().unwrap_or("");
                    comdats.push(OmfComdat {
                        name,
                        selection,
                        segment_index: 0, // TODO
                        offset: 0,
                    });
                }
                
                // Ignored / not yet needed
                MODEND => {}
                MODEND32 => {}
                COMENT => {}
                BAKPAT => {}
                LIBHDR => {}
                LIBDIR => {}
                NBKPAT => {}
                RIDATA => {}
                LIDATA => {}
                LLIDATA => {}
                LLEDATA => {}
                LCOMDEF => {}
                LSEGDEF => {}
                LGRPDEF => {}
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
