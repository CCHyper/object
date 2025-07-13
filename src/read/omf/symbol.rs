use crate::read::{
    Error, ObjectSymbol, ReadRef, SymbolFlags, SymbolIndex, SymbolKind, SymbolScope,
    SymbolSection,
};

use super::OmfFile;

#[derive(Debug)]
pub struct OmfSymbol<'data> {
    pub index: usize,
    pub name: &'data str,
    pub address: u64,
    pub section: SymbolSection,
    pub kind: SymbolKind,
    pub scope: SymbolScope,
    pub flags: SymbolFlags<()>,
}

impl<'data> ObjectSymbol<'data> for OmfSymbol<'data> {
    fn index(&self) -> SymbolIndex {
        SymbolIndex(self.index)
    }

    fn name(&self) -> Result<&'data str, Error> {
        Ok(self.name)
    }

    fn kind(&self) -> SymbolKind {
        self.kind
    }

    fn scope(&self) -> SymbolScope {
        self.scope
    }

    fn section(&self) -> SymbolSection {
        self.section
    }

    fn address(&self) -> u64 {
        self.address
    }

    fn size(&self) -> u64 {
        0
    }

    fn flags(&self) -> SymbolFlags<()> {
        self.flags
    }
}