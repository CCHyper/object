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

// --- Section and Symbol Iterators ---

/// Return an iterator over sections in the OMF file.
/// Currently returns raw SEGDEF/COMDAT segments only (no dedup/group expansion).
pub fn sections(&'data self) -> OmfSectionIterator<'data> {
    OmfSectionIterator {
        iter: self.sections.iter(),
    }
}

/// Iterator over OMF sections.
pub struct OmfSectionIterator<'data> {
    iter: std::slice::Iter<'data, OmfSection>,
}

impl<'data> Iterator for OmfSectionIterator<'data> {
    type Item = &'data OmfSection;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Return an iterator over all symbols in the OMF file.
/// Includes EXTDEF, PUBDEF, and COMDAT names as appropriate.
pub fn symbols(&'data self) -> OmfSymbolIterator<'data> {
    OmfSymbolIterator {
        iter: self.symbols.iter(),
    }
}

/// Iterator over OMF symbols.
pub struct OmfSymbolIterator<'data> {
    iter: std::slice::Iter<'data, OmfSymbol>,
}

impl<'data> Iterator for OmfSymbolIterator<'data> {
    type Item = &'data OmfSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}


// --- ObjectFile Trait Implementation ---

use crate::read::{ObjectFile, ObjectSymbol, ObjectSection, Symbol, SymbolKind, SymbolScope, SymbolSection};
use crate::{Architecture, BinaryFormat, Endianness};

impl<'data> ObjectFile<'data> for OmfFile<'data> {
    type Section = OmfSection<'data>;
    type SectionIterator = OmfSectionIterator<'data>;
    type Symbol = OmfSymbol<'data>;
    type SymbolIterator = OmfSymbolIterator<'data>;

    fn architecture(&self) -> Architecture {
        Architecture::I386 // OMF is used only for 16/32-bit Intel platforms
    }

    fn file_format(&self) -> BinaryFormat {
        BinaryFormat::Omf
    }

    fn is_little_endian(&self) -> bool {
        true // OMF files are always little-endian
    }

    fn entry(&self) -> Option<u64> {
        None // OMF object files do not define entry points
    }

    fn sections(&'data self) -> Self::SectionIterator {
        self.sections()
    }

    fn symbols(&'data self) -> Self::SymbolIterator {
        self.symbols()
    }
}
