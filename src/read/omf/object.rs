//! Trait glue: expose parsed OMF data through the `object::read::ObjectFile` API.

use super::{OmfFile, OmfSection, OmfSymbol};
use crate::read::{
    Architecture, Error, ObjectFile, ObjectSection, ObjectSectionIndex, ObjectSymbol,
    ObjectSymbolTable, SectionIndex, SymbolIndex,
};

impl<'data, R: crate::read::ReadRef<'data>> ObjectFile<'data> for OmfFile<'data, R> {
    type Section = OmfSection<'data>;
    type Symbol  = OmfSymbol<'data>;

    fn architecture(&self) -> Architecture {
        // Intel OMF is almost always 16/32-bit x86. Adjust if you add other CPUs.
        Architecture::I386
    }

    fn sections(&'data self) -> Box<dyn Iterator<Item = Self::Section> + 'data> {
        Box::new(self.sections())
    }

    fn section_by_index(&'data self, index: SectionIndex) -> Result<Self::Section, Error> {
        self.sections().nth(index.0).ok_or(Error("invalid section index"))
    }

    fn symbol_table(&'data self) -> Option<&dyn ObjectSymbolTable<'data, Symbol = Self::Symbol>> {
        Some(self)
    }
}
