use crate::read::{
    Error, ObjectSection, ObjectSectionIndex, ObjectSegment, ReadRef, Relocation, RelocationEncoding,
    RelocationKind, SectionFlags, SectionIndex, SymbolIndex,
};

use super::OmfFile;

#[derive(Debug)]
pub struct OmfSection<'data> {
    pub index: usize,
    pub name: &'data str,
    pub data: &'data [u8],
    pub flags: SectionFlags,
    pub relocs: Vec<OmfRelocation>,
}

/// Relocation emitted by a FIXUPP sub-record.
///
/// *Only segment-relative fixups are decoded for now; threaded or
/// external/symbol fixups are TODO.*
#[derive(Debug)]
pub struct OmfRelocation {
    pub offset: u32,          // location within `data`
    pub target_segment: u16,  // 1-based SEGDEF index
    pub kind:  RelocationKind,
    pub encoding: RelocationEncoding,
    pub size:  u8,
    pub addend: i64,
}

impl<'data> ObjectSection<'data> for OmfSection<'data> {
    type Relocation = OmfRelocation;

    fn index(&self) -> SectionIndex {
        SectionIndex(self.index)
    }

    fn name(&self) -> Result<&'data str, Error> {
        Ok(self.name)
    }

    fn data(&self) -> Result<&'data [u8], Error> {
        Ok(self.data)
    }

    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn align(&self) -> u64 {
        1
    }

    fn flags(&self) -> SectionFlags {
        self.flags
    }

    fn relocations(&self) -> Box<dyn Iterator<Item = (u64, &Self::Relocation)> + '_> {
        Box::new(self.relocs.iter().map(|r| (r.offset, r)))
    }

    fn segment(&self) -> Option<ObjectSegment<'data>> {
        None
    }
}