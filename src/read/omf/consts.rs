// OMF object record type constants.
// These appear in the first byte of each record and determine how the body is parsed.

/// Header records (non-data).
pub const THEADR:   u8 = 0x80; // Module header (name of source file)
pub const COMENT:   u8 = 0x88; // Comment metadata or linker hints
pub const MODEND:   u8 = 0x8A; // End of module (may also encode entry point)

/// Symbol definitions and declarations.
pub const EXTDEF:   u8 = 0x8C; // External symbol declaration
pub const PUBDEF:   u8 = 0x90; // Public (global) symbol definition
pub const COMDEF:   u8 = 0xB0; // Common uninitialized symbol

/// Segment and group records.
pub const SEGDEF:   u8 = 0x98; // Defines a new code/data segment
pub const GRPDEF:   u8 = 0x9A; // Defines a named group of segments
pub const LEDATA:   u8 = 0xA0; // Segment data
pub const LIDATA:   u8 = 0xA2; // Iterated data block
pub const LLIDATA:  u8 = 0xA3; // Extended iterated data

/// Relocation records.
pub const FIXUPP:   u8 = 0x9C; // Relocation/fixup instructions
pub const BAKPAT:   u8 = 0xA4; // Backpatch (rare)

/// COMDAT-related extensions.
pub const COMDAT:   u8 = 0xC2; // Code/data fragment for deduplication
pub const LCOMDEF:  u8 = 0xB4; // Extended COMDEF (32-bit or segmented)
pub const LSEGDEF:  u8 = 0x9D; // Extended SEGDEF
pub const LGRPDEF:  u8 = 0x9E; // Extended GRPDEF

/// Library archive records (used in .LIB files).
pub const LIBHDR:   u8 = 0xF0; // Library header
pub const LIBDIR:   u8 = 0xF2; // Table of contents / module index

/// Miscellaneous/debug records.
pub const NBKPAT:   u8 = 0xA6; // Named backpatch (rare)
pub const LLEDATA:  u8 = 0xA1; // Extended LEDATA (larger offsets)
pub const RIDATA:   u8 = 0xA8; // Reserved?
pub const IDXTYP:   u8 = 0xF4; // Index type descriptor
pub const LIDRNAME: u8 = 0xF6; // Index record: name
pub const LIDRTYP:  u8 = 0xF8; // Index record: type
pub const LIDRVAL:  u8 = 0xFA; // Index record: value
