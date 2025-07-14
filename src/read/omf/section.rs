use crate::read::{
    Error, ObjectSection, ObjectSectionIndex, ObjectSegment, ReadRef, Relocation, RelocationEncoding,
    RelocationKind, SectionFlags, SectionIndex, SymbolIndex,
};
use crate::read::SectionFlags;
use crate::read::{ObjectSegment, SegmentFlags};

use super::OmfFile;

#[derive(Debug)]
pub struct OmfSection<'data> {
    pub index: usize,
    pub name: &'data str,
    pub data: &'data [u8],
    pub flags: SectionFlags,
    pub relocs: Vec<OmfRelocation>,
}

pub enum OmfFixupTarget {
    Segment(u16),
    Group(u16),
    Symbol(u16),
}

pub enum OmfFixupFrame {
    Segment(u16),
    Group(u16),
    Symbol(u16),
    Location,
}

/// Relocation emitted by a FIXUPP sub-record.
///
/// *Only segment-relative fixups are decoded for now; threaded or
/// external/symbol fixups are TODO.*
#[derive(Debug)]
pub struct OmfRelocation {
    pub offset: u32,
    pub target: OmfFixupTarget,
    pub frame: Option<OmfFixupFrame>,
    pub kind:  RelocationKind,
    pub encoding: RelocationEncoding,
    pub size:  u8,
    pub addend: i64,
}

// -----------------------------------------------------------------------------
// ObjectSection Trait Implementation
//
// The `ObjectSection` trait defines how sections are exposed to consumers
// of the `object` crate's read interface.
//
// In OMF, sections correspond 1:1 with SEGDEF + LEDATA/COMDAT combinations.
// We implement this on `OmfSection` to enable consumers to access section
// data, relocations, names, and flags in a format-agnostic way.
// -----------------------------------------------------------------------------

impl<'data> ObjectSection<'data> for OmfSection<'data> {
    /// Type used to represent relocations in this format.
    type Relocation = OmfRelocation;

    /// Return this section's numeric index within the object file.
    fn index(&self) -> SectionIndex {
        SectionIndex(self.index)
    }

    /// Return the name of this section, parsed from SEGDEF or COMDAT headers.
    fn name(&self) -> Result<&'data str, Error> {
        Ok(self.name)
    }

    /// Return a borrowed slice of raw bytes for this section.
    fn data(&self) -> Result<&'data [u8], Error> {
        Ok(self.data)
    }

    /// Return the virtual address this section should be loaded at.
    /// OMF object files do not assign fixed runtime addresses; return 0.
    fn address(&self) -> u64 {
        0
    }

    /// Return the number of bytes in the section's contents.
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Return the required memory alignment of this section.
    /// OMF does not encode alignment, so we assume byte-aligned (1).
    fn align(&self) -> u64 {
        1
    }

    /// Return section flags.
    /// These are set heuristically by the parser; OMF does not provide real flags.
    fn flags(&self) -> SectionFlags {
        self.flags
    }

    /// Return an iterator over this section’s relocation entries.
    /// Each relocation adjusts a target offset in the section.
    fn relocations(&self) -> Box<dyn Iterator<Item = (u64, &Self::Relocation)> + '_> {
        Box::new(self.relocs.iter().map(|r| (r.offset, r)))
    }

    /// Return an owning reference to the segment this section belongs to.
    /// Not used in OMF yet; all segments are treated independently.
    fn segment(&self) -> Option<ObjectSegment<'data>> {
        None
    }
}

// -----------------------------------------------------------------------------
// ObjectSegment Trait Implementation
//
// In the `object` crate, a “segment” is a top-level binary region
// (e.g., ELF PT_LOAD, COFF section).  For OMF, each SEGDEF/LEDATA pair
// (and each COMDAT-as-section) maps 1-to-1 with `OmfSection`,
// so we can expose the same struct as both a Section *and* a Segment.
// -----------------------------------------------------------------------------
impl<'data> ObjectSegment<'data> for OmfSection<'data> {
    /// Segment name (same string as the section’s).
    fn name(&self) -> Result<&'data str, ()> {
        Ok(self.name)
    }

    /// Segment virtual address.
    /// OMF object files don’t have fixed runtime addresses, so return 0.
    fn address(&self) -> u64 {
        0
    }

    /// Size of the segment in bytes.
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Alignment requirement.  OMF doesn’t encode explicit alignment,
    /// so we default to 1-byte alignment.
    fn align(&self) -> u64 {
        1
    }

    /// Raw segment data.
    fn data(&self) -> Result<&'data [u8], ()> {
        Ok(self.data)
    }

    /// Segment permission / attribute flags.
    /// OMF has no per-segment permission bits, so expose `SegmentFlags::None`.
    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }
}
