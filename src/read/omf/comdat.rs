use alloc::vec::Vec;

use crate::read::{self, Error, Result};
use crate::{omf, ComdatKind, ObjectComdat, ReadRef, SectionIndex, SymbolIndex};

use super::relocation::OmfFixup;
use super::OmfFile;

/// A COMDAT (communal data) section
#[derive(Debug, Clone)]
pub(super) struct OmfComdatData<'data> {
    /// Symbol name (raw bytes from the names table)
    pub(super) name: &'data [u8],
    /// 1-based index into the LNAMES table for this COMDAT's public name.
    #[allow(dead_code)]
    pub(super) name_index: u16,
    /// Segment index where this COMDAT belongs
    pub(super) segment_index: u16,
    /// Selection/allocation method
    pub(super) selection: OmfComdatSelection,
    /// Alignment
    #[allow(dead_code)]
    pub(super) alignment: omf::SegmentAlignment,
    /// Inline COMDAT data slices (code/data bytes from the COMDAT record body).
    /// Multiple slices when continuation records (flags bit 1) are present.
    pub(super) data_slices: Vec<&'data [u8]>,
    /// Index into the symbol table for the defining symbol, if resolved by name.
    pub(super) symbol_index: Option<usize>,
    /// Fixups (relocations) for this COMDAT's inline data.
    pub(super) relocations: Vec<OmfFixup>,
    /// Line number entries from LINSYM records: (line_number, code_offset).
    pub(super) line_numbers: Vec<(u16, u32)>,
}

/// COMDAT selection methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OmfComdatSelection {
    /// Explicit: may not be combined, produce error if multiple definitions
    Explicit = 0,
    /// Use any: pick any instance
    UseAny = 1,
    /// Same size: all instances must be same size
    SameSize = 2,
    /// Exact match: all instances must have identical content
    ExactMatch = 3,
}

/// A COMDAT section in an OMF file.
#[derive(Debug)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
    _phantom: core::marker::PhantomData<&'data ()>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> ComdatKind {
        let comdat = &self.file.comdats[self.index];
        match comdat.selection {
            OmfComdatSelection::Explicit => ComdatKind::NoDuplicates,
            OmfComdatSelection::UseAny => ComdatKind::Any,
            OmfComdatSelection::SameSize => ComdatKind::SameSize,
            OmfComdatSelection::ExactMatch => ComdatKind::ExactMatch,
        }
    }

    fn symbol(&self) -> SymbolIndex {
        let comdat = &self.file.comdats[self.index];
        match comdat.symbol_index {
            Some(idx) => SymbolIndex(idx),
            // No matching symbol found; SymbolIndex(0) is a safe default that at
            // worst returns the first symbol rather than panicking.
            None => SymbolIndex(0),
        }
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        let comdat = &self.file.comdats[self.index];
        Ok(comdat.name)
    }

    fn name(&self) -> Result<&'data str> {
        let comdat = &self.file.comdats[self.index];
        core::str::from_utf8(comdat.name).map_err(|_| Error("Invalid UTF-8 in COMDAT name"))
    }

    fn sections(&self) -> Self::SectionIterator {
        let comdat = &self.file.comdats[self.index];
        OmfComdatSectionIterator {
            segment_index: (comdat.segment_index as usize).checked_sub(1),
            returned: false,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// An iterator over COMDAT sections.
#[derive(Debug)]
pub struct OmfComdatIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatIterator<'data, 'file, R> {
    type Item = OmfComdat<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.comdats.len() {
            let comdat = OmfComdat {
                file: self.file,
                index: self.index,
                _phantom: core::marker::PhantomData,
            };
            self.index += 1;
            Some(comdat)
        } else {
            None
        }
    }
}

/// An iterator over sections in a COMDAT.
#[derive(Debug)]
pub struct OmfComdatSectionIterator<'data, 'file, R: ReadRef<'data>> {
    segment_index: Option<usize>,
    returned: bool,
    _phantom: core::marker::PhantomData<(&'data (), &'file (), R)>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.returned {
            self.returned = true;
            self.segment_index.map(|idx| SectionIndex(idx + 1))
        } else {
            None
        }
    }
}
