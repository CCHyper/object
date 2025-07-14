//! COMMENT record parsing for OMF object files.
//! Supports common Microsoft, Borland, and Watcom variants.
//! COMMENT records contain metadata, compiler info, copyright, etc.

use crate::read::Result;

/// Known COMMENT kinds found in OMF files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmfCommentKind {
    CompilerInfo,
    Copyright,
    LinkerInfo,
    Other(u8),
}

/// Parsed COMMENT metadata (subset of known encodings).
#[derive(Debug)]
pub struct OmfComment<'data> {
    pub kind: OmfCommentKind,
    pub data: &'data [u8],
}

/// Parses a COMMENT record body and classifies its kind.
///
/// This implementation supports subtyped classes used by MS/Borland/Watcom.
/// If the class is unknown or malformed, returns `None`.
pub fn parse_comment<'data>(body: &'data [u8]) -> Option<OmfComment<'data>> {
    if body.len() < 2 {
        return None;
    }

    let class = body[0];
    let subtype = body[1];
    let data = &body[2..];

    let kind = match class {
        0x00 => OmfCommentKind::CompilerInfo,
        0x01 => OmfCommentKind::Copyright,
        0x9A if is_known_subtyped_class(subtype) => OmfCommentKind::LinkerInfo,
        other => OmfCommentKind::Other(other),
    };

    Some(OmfComment { kind, data })
}

/// Returns true if this subtype is known in class 0x9A (MS/Borland style).
fn is_known_subtyped_class(subtype: u8) -> bool {
    matches!(
        subtype,
        0x00 | // Linker Version
        0x01 | // Memory model
        0x02 | // DOSSEG
        0x03 | // Filename
        0x9A | // Borland .MODEL
        0x9B | // Watcom signature
        0x9C   // Pharlap or other signatures
    )
}
