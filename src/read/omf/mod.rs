use crate::read::ReadRef;
use crate::{Result, Error};

/// All Intel OMF record types (16-bit & 32-bit).
#[derive(Debug)]
#[non_exhaustive]
pub enum OmfRecord<'data> {
    Theadr(&'data [u8]),
    Comdat(&'data [u8]),
    Segdef(&'data [u8]),
    Pubdef(&'data [u8]),
    Extdef(&'data [u8]),
    Lnames(&'data [u8]),
    Fixupp(&'data [u8]),
    Modend(&'data [u8]),
    Unknown(u8, &'data [u8]),
}

/// A parsed Intel OMF file.
pub struct OmfFile<'data, R: ReadRef<'data>> {
    data: R,
    pub records: Vec<OmfRecord<'data>>,
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
            offset += 3;
            if offset + len > bytes.len() {
                return Err(Error("OMF record length overflow"));
            }
            let body = &bytes[offset..offset + len];
            offset += len;

            let record = match rec_type {
                0x80 => OmfRecord::Theadr(body),
                0x8A => OmfRecord::Segdef(body),
                0x8C => OmfRecord::Pubdef(body),
                0x8F => OmfRecord::Extdef(body),
                0x96 => OmfRecord::Lnames(body),
                0x9C => OmfRecord::Fixupp(body),
                0x8E => OmfRecord::Modend(body),
                _ => OmfRecord::Unknown(rec_type, body),
            };

            records.push(record);
        }

        Ok(Self { data, records })
    }
}
