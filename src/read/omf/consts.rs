// OMF (Object Module Format) Record Type Constants
// -------------------------------------------------
// These record types define various kinds of data and metadata in OMF object files,
// used by Microsoft, Borland, Watcom, and other toolchains.
// Each value is a unique 8-bit identifier used at the start of a record.

/// 0x80: Comment record — tool/vendor info, debug info, or misc annotations.
pub const COMENT: u8 = 0x88;

/// 0x8A: Defines an external symbol (used but not defined here).
pub const EXTDEF: u8 = 0x8C;
/// 0xA0: 32-bit version of EXTDEF.
pub const LEXTDEF: u8 = 0xA0;

/// 0x8C: Defines a segment name.
pub const LNAMES: u8 = 0x96;

/// 0x98: Segment definition (SEGDEF).
pub const SEGDEF: u8 = 0x98;
/// 0x99: Segment definition (SEGDEF) with 32-bit addressing flag.
pub const SEGDEF32: u8 = 0x99;

/// 0x9A: Group definition (GRPDEF).
pub const GRPDEF: u8 = 0x9A;
/// 0xA2: Long group definition (rare, not always emitted).
pub const LGRPDEF: u8 = 0xA2;

/// 0x9C: Public symbol definition (PUBDEF).
pub const PUBDEF: u8 = 0x90;
/// 0xA6: Long public symbol definition (32-bit).
pub const LPUBDEF: u8 = 0xA6;

/// 0x9E: Segment data record (LEdata).
pub const LEDATA: u8 = 0xA0;
/// 0xA8: Large/long LEDATA record (32-bit data offset).
pub const LLEDATA: u8 = 0xA8;

/// 0xA2: Fixup (relocation) information.
pub const FIXUPP: u8 = 0x9C;

/// 0x9D: Common (BSS-style) uninitialized variable definition.
pub const COMDEF: u8 = 0xB0;
/// 0xB2: Long COMDEF.
pub const LCOMDEF: u8 = 0xB2;

/// 0xC2: COMDAT record — reusable code or data.
pub const COMDAT: u8 = 0xC2;

/// 0x8A / 0x8B: Module end records (16/32-bit variants).
pub const MODEND: u8 = 0x8A;
pub const MODEND32: u8 = 0x8B;

/// 0x94: Threaded relocation (not handled yet).
pub const THREAD: u8 = 0x94;

/// 0x92: Repeated/iterated data — structured fill block.
pub const LIDATA: u8 = 0xA2;
pub const LLIDATA: u8 = 0xA9;

/// 0xA4–0xAB: Misc Borland/Watcom linker/debug records.
pub const BAKPAT: u8 = 0xA4;
pub const NBKPAT: u8 = 0xA6;
pub const LIBHDR: u8 = 0xF0;
pub const LIBDIR: u8 = 0xF1;
pub const RIDATA: u8 = 0xF2;

/// 0xFC–0xFE: Borland incremental linker.
pub const LIDRNAME: u8 = 0xFC;
pub const LIDRTYP: u8 = 0xFD;
pub const LIDRVAL: u8 = 0xFE;

/// 0x86: Theadr — specifies the name of the source module.
pub const THEADR: u8 = 0x80;
