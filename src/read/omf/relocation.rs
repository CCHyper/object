use crate::read::ReadRef;
use crate::{
    omf, Relocation, RelocationEncoding, RelocationFlags, RelocationKind, RelocationTarget,
    SymbolIndex,
};

use super::file::{FrameMethod, TargetMethod};
use super::OmfFile;

/// An OMF fixup (relocation entry).
#[derive(Debug, Clone)]
pub(super) struct OmfFixup {
    /// Offset in segment where fixup is applied
    pub(super) offset: u32,
    /// Location type (what to patch)
    pub(super) location: omf::FixupLocation,
    /// Frame method
    pub(super) frame_method: FrameMethod,
    /// Target method
    pub(super) target_method: TargetMethod,
    /// Frame index (meaning depends on frame_method)
    pub(super) frame_index: u16,
    /// Target index (meaning depends on target_method)
    pub(super) target_index: u16,
    /// Target displacement
    pub(super) target_displacement: u32,
    /// M-bit: true for segment-relative, false for PC-relative
    pub(super) is_segment_relative: bool,
}

/// An iterator over OMF relocations.
#[derive(Debug)]
pub struct OmfRelocationIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) segment_index: usize,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let relocations = &self.file.segments[self.segment_index].relocations;
        let reloc = relocations.get(self.index)?;
        self.index += 1;

        let (mut kind, size, base_addend) = match reloc.location {
            omf::FixupLocation::LowByte => (RelocationKind::Absolute, 8, 0),
            omf::FixupLocation::HighByte => (RelocationKind::Absolute, 8, 0),
            omf::FixupLocation::Offset | omf::FixupLocation::LoaderOffset => {
                if reloc.is_segment_relative {
                    (RelocationKind::SectionOffset, 16, 0)
                } else {
                    // Self-relative (PC-relative) 16-bit fixup.
                    // The OMF `target_displacement` field is the explicit addend;
                    // no extra adjustment is needed here.  Adding −2 would cause
                    // external-symbol addends to display as "sym-2" and would make
                    // intra-section targets negative (rejected by u64 conversion).
                    (RelocationKind::Relative, 16, 0)
                }
            }
            omf::FixupLocation::Offset32 | omf::FixupLocation::LoaderOffset32 => {
                if reloc.is_segment_relative {
                    (RelocationKind::SectionOffset, 32, 0)
                } else {
                    // Self-relative (PC-relative) 32-bit fixup — same reasoning as
                    // the 16-bit case above; the original −4 was incorrect.
                    (RelocationKind::Relative, 32, 0)
                }
            }
            omf::FixupLocation::Base => {
                if matches!(reloc.target_method, TargetMethod::SegmentIndex) {
                    (RelocationKind::SectionIndex, 16, 0)
                } else {
                    (RelocationKind::Unknown, 16, 0)
                }
            }
            omf::FixupLocation::Pointer => (RelocationKind::Absolute, 32, 0),
            omf::FixupLocation::Pointer48 => (RelocationKind::Absolute, 48, 0),
        };

        if matches!(kind, RelocationKind::SectionOffset)
            && !matches!(reloc.target_method, TargetMethod::SegmentIndex)
        {
            kind = RelocationKind::Unknown;
        }

        if matches!(
            reloc.location,
            omf::FixupLocation::LoaderOffset | omf::FixupLocation::LoaderOffset32
        ) && matches!(reloc.frame_method, FrameMethod::ExternalIndex)
        {
            kind = RelocationKind::Unknown;
        }

        if matches!(reloc.target_method, TargetMethod::GroupIndex) {
            kind = RelocationKind::Unknown;
        }

        let target = match reloc.target_method {
            TargetMethod::SegmentIndex => {
                // target_index is 1-based per OMF spec (0 means "no segment").
                // Use the synthetic section symbol so consumers (e.g. objdiff)
                // can resolve the target via Symbol handling, which is the
                // standard path used by COFF/ELF.
                let idx = reloc.target_index as usize;
                if idx > 0 && idx <= self.file.segments.len() {
                    let sym_idx = self.file.segment_symbol_map[idx - 1];
                    RelocationTarget::Symbol(SymbolIndex(sym_idx))
                } else {
                    RelocationTarget::Absolute
                }
            }
            TargetMethod::ExternalIndex => {
                // External indices in OMF are 1-based indices into the external-name table
                if let Some(symbol) = self.file.external_symbol(reloc.target_index) {
                    RelocationTarget::Symbol(SymbolIndex(symbol.symbol_index))
                } else {
                    RelocationTarget::Absolute
                }
            }
            TargetMethod::GroupIndex | TargetMethod::FrameNumber => RelocationTarget::Absolute,
        };

        let fixup_frame = match reloc.frame_method {
            FrameMethod::SegmentIndex => omf::FixupFrame::Segment(reloc.frame_index),
            FrameMethod::GroupIndex => omf::FixupFrame::Group(reloc.frame_index),
            FrameMethod::ExternalIndex => omf::FixupFrame::External(reloc.frame_index),
            FrameMethod::FrameNumber => omf::FixupFrame::FrameNumber(reloc.frame_index),
            FrameMethod::Location => omf::FixupFrame::Location,
            FrameMethod::Target => omf::FixupFrame::Target,
        };

        let fixup_target = match reloc.target_method {
            TargetMethod::SegmentIndex => omf::FixupTarget::Segment(reloc.target_index),
            TargetMethod::GroupIndex => omf::FixupTarget::Group(reloc.target_index),
            TargetMethod::ExternalIndex => omf::FixupTarget::External(reloc.target_index),
            TargetMethod::FrameNumber => omf::FixupTarget::FrameNumber(reloc.target_index),
        };

        // OMF fixups combine TWO sources for the addend:
        //   1. `target_displacement` — explicit field in the FIXUPP record
        //   2. Pre-existing bytes at the fixup location in the LEDATA record
        // The linker adds the computed target address to both.  We read the
        // data bytes here so that offsets like `Symbol+1` are preserved.
        let data_byte_count = match reloc.location {
            omf::FixupLocation::LowByte | omf::FixupLocation::HighByte => 1u32,
            omf::FixupLocation::Offset | omf::FixupLocation::LoaderOffset => 2,
            omf::FixupLocation::Offset32 | omf::FixupLocation::LoaderOffset32 => 4,
            _ => 0,
        };
        let data_addend = if data_byte_count > 0 {
            self.file.segments[self.segment_index].read_addend_at(reloc.offset, data_byte_count)
        } else {
            0
        };

        let relocation = Relocation {
            kind,
            encoding: RelocationEncoding::Generic,
            size,
            target,
            subtractor: None,
            addend: (reloc.target_displacement as i64) + base_addend + data_addend,
            implicit_addend: false,
            flags: RelocationFlags::Omf {
                location: reloc.location,
                mode: if reloc.is_segment_relative {
                    omf::FixupMode::SegmentRelative
                } else {
                    omf::FixupMode::SelfRelative
                },
                frame: fixup_frame,
                target: fixup_target,
                // target_displacement: reloc.target_displacement,
            },
        };

        Some((reloc.offset as u64, relocation))
    }
}
