//! Minimal parser for OMF FIXUPP records.
//! Supports basic 16-bit/32-bit segment-relative fixups.

#[derive(Debug)]
pub enum OmfFixup {
    /// A relocation to a segment + offset (absolute).
    SegmentOffset {
        location: u16,
        is_32bit: bool,
        target_segment: u8,
        displacement: u16,
    },
}

impl OmfFixup {
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut out = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let kind = data[i];
            i += 1;

            if kind & 0x80 == 0 {
                continue; // skip thread records
            }

            let loc_type = (kind >> 3) & 0b11;
            let is_32bit = loc_type == 0b10;

            if i >= data.len() {
                break;
            }
            let loc_off = u16::from_le_bytes([data[i], data[i + 1]]);
            i += 2;

            if i >= data.len() {
                break;
            }
            let tgt_desc = data[i];
            i += 1;

            if tgt_desc & 0x04 != 0 {
                continue; // unsupported external fixup
            }

            if i + 2 > data.len() {
                break;
            }

            let seg = data[i];
            let disp = data[i + 1] as u16;
            i += 2;

            out.push(OmfFixup::SegmentOffset {
                location: loc_off,
                is_32bit,
                target_segment: seg,
                displacement: disp,
            });
        }

        out
    }
}

/// State for handling threaded fixups in OMF.
/// In OMF, a "thread" record allows reusing a frame or target index for multiple fixups,
/// reducing object file size.
///
/// Each thread is identified by a Thread Index (0–3 for frame, 0–7 for target),
/// and stores either a segment/group/symbol index.
///
/// Thread fixups are optional. If missing, fixups specify explicit frame/target.
///
/// NOTE: This is currently unused — FIXUPP handling skips thread records.
/// See the `FIXUPP` match arm in `mod.rs`.
#[derive(Default, Debug)]
pub struct ThreadState {
    /// Frame threads (indexed 0..4) — reused in fixups when frame = 0b11
    pub frame_threads: [Option<OmfFixupFrame>; 4],

    /// Target threads (indexed 0..8) — reused when target = 0b11
    pub target_threads: [Option<OmfFixupTarget>; 8],
}
