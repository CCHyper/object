use crate::read::ReadRef;

/// Placeholder for a parsed OMF section (segment).
#[derive(Debug)]
pub struct OmfSection<'data> {
    pub name: &'data str,
    pub data: &'data [u8],
    pub segment_index: u8,
    pub is_code: bool,
    pub is_32bit: bool,
}
