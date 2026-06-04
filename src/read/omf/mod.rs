//! Support for reading OMF files.

mod comdat;
pub use comdat::{OmfComdat, OmfComdatIterator, OmfComdatSectionIterator};

mod file;
pub use file::OmfFile;

mod relocation;
pub use relocation::OmfRelocationIterator;

mod section;
pub use section::{OmfSection, OmfSectionIterator};

mod segment;
pub use segment::{OmfSegment, OmfSegmentIterator, OmfSegmentRef};

mod symbol;
pub use symbol::{OmfSymbol, OmfSymbolClass, OmfSymbolIterator, OmfSymbolTable};
