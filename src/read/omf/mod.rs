mod consts;
use consts::*;

//! Intel OMF (Object Module Format) parser (16-bit and 32-bit).
use crate::read::{self, ReadRef};
use crate::{Result, Error};
use super::omf::{OmfRecord, OmfSection, OmfSymbol};

mod section;
mod symbol;

pub use section::OmfSection;
pub use symbol::OmfSymbol;

#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data>> {
    pub data: R,
    pub records: Vec<OmfRecord<'data>>,
    pub module_name: Option<&'data str>,
    pub lnames: Vec<&'data str>,
    pub sections: Vec<OmfSection<'data>>,
    pub symbols: Vec<OmfSymbol<'data>>,
}

impl<'data, R: ReadRef<'data>> OmfFile<'data, R> {
    pub fn peek(data: R) -> Result<(), ()> {
        if let Some(&b) = data.as_slice().get(0) {
            if (0x80..=0x9F).contains(&b) {
                return Ok(());
            }
        }
        Err(())
    }

    pub fn parse(data: R) -> Result<Self> {
        let bytes = data.as_slice();
        let mut offset = 0;
        let mut records = Vec::new();

        while offset + 3 <= bytes.len() {
            let rec_type = bytes[offset];
            let len = u16::from_le_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
            let end = offset + 3 + len;
            if end > bytes.len() {
                return Err(Error("Truncated OMF record"));
            }
            let body = &bytes[offset + 3..end];
            records.push(OmfRecord::from_raw(rec_type, body));
            offset = end;
        }

        let mut module_name = None;
        let mut lnames = Vec::new();
        let mut sections = Vec::new();
        let mut symbols = Vec::new();

        for rec in &records {
            match rec {
                OmfRecord::Theadr(data) => {
                    module_name = Some(read::parse_string(data).map_err(|_| Error("Invalid THEADR"))?);
                }
                OmfRecord::Lnames(data) => {
                    let mut pos = 0;
                    while pos < data.len() {
                        let name = read::parse_string(&data[pos..]).map_err(|_| Error("Invalid LNAME"))?;
                        pos += 1 + name.len();
                        lnames.push(name);
                    }
                }
                OmfRecord::Segdef(data) => {
                    let seg = OmfSection::parse(data, &lnames)?;
                    sections.push(seg);
                }
                OmfRecord::Ledata(data) => {
                    if let Some(section) = sections.last_mut() {
                        section.data = *data;
                    }
                }
                OmfRecord::Pubdef(data) => {
                    let mut sym = OmfSymbol::parse(data, &lnames)?;
                    symbols.append(&mut sym);
                }
                _ => {}
            }
        }

        Ok(Self {
            data,
            records,
            module_name,
            lnames,
            sections,
            symbols,
        })
    }
}

/// High-level classification of each OMF record.
#[derive(Debug)]
pub enum OmfRecord<'data> {
    Theadr(&'data [u8]),
    Comment(&'data [u8]),
    Pubdef(&'data [u8]),
    Segdef(&'data [u8]),
    Extdef(&'data [u8]),
    Lnames(&'data [u8]),
    Fixupp(&'data [u8]),
    Modend(&'data [u8]),
    Ledata(&'data [u8]),
    Unknown(u8, &'data [u8]),
}

impl<'data> OmfRecord<'data> {
    pub fn from_raw(kind: u8, data: &'data [u8]) -> Self {
        match kind {
            RECORD_THEADR                     => Self::Theadr(data),
            RECORD_COMENT                     => Self::Comment(data),
            RECORD_PUBDEF16 | RECORD_PUBDEF32 => Self::Pubdef(data),
            RECORD_SEGDEF16 | RECORD_SEGDEF32 => Self::Segdef(data),
            RECORD_EXTDEF                     => Self::Extdef(data),
            RECORD_LNAMES                     => Self::Lnames(data),
            RECORD_FIXUPP                     => Self::Fixupp(data),
            RECORD_MODEND                     => Self::Modend(data),
            RECORD_LEDATA16 | RECORD_LEDATA32 => Self::Ledata(data),
            _ => Self::Unknown(kind, data),
        }
    }
}
