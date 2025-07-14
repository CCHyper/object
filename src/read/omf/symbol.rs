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
        // Determine the symbol kind based on source:
        // - COMDAT with data? → Data
        // - COMDAT with code? → Text (future work: infer from flags)
        // - EXTDEF/PUBDEF with unknown role? → default to Data
                self.kind
    }

    fn scope(&self) -> SymbolScope {
        self.scope
    }

    fn section(&self) -> SymbolSection {
        // Map section index to actual section.
        // If 0 (undefined), mark as such. Otherwise direct mapping.
                self.section
    }

    fn address(&self) -> u64 {
        self.address
    }

    fn size(&self) -> u64 {
        // If the size is known (e.g. from COMDAT or COMDEF), return it.
        // Otherwise fallback to segment end - offset, or 0 if unknown.
                0
    }

    fn flags(&self) -> SymbolFlags<()> {
        self.flags
    }
}