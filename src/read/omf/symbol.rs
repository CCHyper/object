use crate::read::ReadRef;

/// Placeholder for a parsed OMF symbol.
#[derive(Debug)]
pub struct OmfSymbol<'data> {
    pub name: &'data str,
    pub segment_index: u8,
    pub offset: u32,
    pub is_public: bool,
}
