use alloc::{vec, vec::Vec};

use crate::read::{self, ObjectSegment, ReadRef, Result};
use crate::{omf, Permissions, SegmentFlags};

use super::relocation::OmfFixup;
use super::OmfFile;

/// An OMF segment definition
#[derive(Debug, Clone)]
pub struct OmfSegment<'data> {
    /// Segment name index (into names table)
    pub(super) name_index: u16,
    /// Class name index (into names table)
    pub(super) class_index: u16,
    /// Overlay name index (into names table)
    #[allow(unused)] // TODO
    pub(super) overlay_index: u16,
    /// Segment alignment
    pub(super) alignment: omf::SegmentAlignment,
    /// Segment combination
    #[allow(dead_code)]
    pub(super) combination: omf::SegmentCombination,
    /// Whether this is a 32-bit segment
    pub(super) use32: bool,
    /// Segment length
    pub(super) length: u32,
    /// Segment data chunks (offset, data)
    /// Multiple LEDATA/LIDATA records can contribute to a single segment
    pub(super) data_chunks: Vec<(u32, OmfDataChunk<'data>)>,
    /// Relocations for this segment
    pub(super) relocations: Vec<OmfFixup>,
    /// True if this segment was synthesised from a COMDAT record rather than
    /// a real SEGDEF.  Used by `segment_section_kind` to classify it as code
    /// without relying on class-name heuristics.
    pub(super) is_comdat: bool,
    /// True if this segment was synthesised for a COMDEF communal variable.
    /// Borland C++ emits LEDATA/LIDATA records whose segment index encodes
    /// a communal reference (decoded index > 0x4000) instead of a SEGDEF index.
    /// These synthetic segments hold the initialisation data for the communal.
    #[allow(dead_code)]
    pub(super) is_communal: bool,
    /// Line number entries from LINNUM records: (line_number, segment_offset).
    pub(super) line_numbers: Vec<(u16, u32)>,
}

/// Data chunk for a segment
#[derive(Debug, Clone)]
pub(super) enum OmfDataChunk<'data> {
    /// Direct data from LEDATA record
    Direct(&'data [u8]),
    /// Compressed/iterated data from LIDATA record (needs expansion)
    Iterated(&'data [u8]),
}

impl<'data> OmfSegment<'data> {
    /// Get the raw data of the segment if it's a single contiguous chunk
    pub fn get_single_chunk(&self) -> Option<&'data [u8]> {
        if self.data_chunks.len() == 1 {
            let (offset, chunk) = &self.data_chunks[0];
            if *offset == 0 {
                match chunk {
                    OmfDataChunk::Direct(data) if data.len() == self.length as usize => {
                        return Some(data);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Return a byte slice covering `[start, start+len)` within this segment,
    /// provided the range lives entirely inside a single `Direct` LEDATA chunk.
    ///
    /// Used by alignment-padding trimming to access a symbol's bytes without
    /// requiring the entire segment to be a single contiguous chunk — Borland
    /// C++ routinely splits `_TEXT` across many LEDATA records, but individual
    /// functions are still emitted inside one LEDATA chunk each.
    pub(super) fn get_range_single_chunk(&self, start: u32, len: u32) -> Option<&'data [u8]> {
        let end = start.checked_add(len)?;
        for &(chunk_offset, ref chunk) in &self.data_chunks {
            if let OmfDataChunk::Direct(data) = chunk {
                let chunk_end = chunk_offset + data.len() as u32;
                if start >= chunk_offset && end <= chunk_end {
                    let local_start = (start - chunk_offset) as usize;
                    let local_end = (end - chunk_offset) as usize;
                    return Some(&data[local_start..local_end]);
                }
            }
        }
        None
    }

    /// Copy `[start, start+len)` into a newly allocated buffer, gathering bytes
    /// from every `Direct` chunk that overlaps the range.
    ///
    /// Returns `None` if the range is not fully covered (a gap, an `Iterated`
    /// chunk inside the range, or the range extends past the covered bytes).
    /// Used as a fallback by alignment-padding trimming when a single function
    /// straddles a LEDATA chunk boundary.
    pub(super) fn copy_range_bytes(&self, start: u32, len: u32) -> Option<Vec<u8>> {
        let end = start.checked_add(len)?;
        // Collect all Direct chunks that overlap [start, end), paired with
        // their offsets, then sort by offset so we can walk them contiguously.
        let mut overlapping: Vec<(u32, &[u8])> = Vec::new();
        for &(chunk_offset, ref chunk) in &self.data_chunks {
            if let OmfDataChunk::Direct(data) = chunk {
                let chunk_end = chunk_offset + data.len() as u32;
                if chunk_offset < end && chunk_end > start {
                    overlapping.push((chunk_offset, data));
                }
            }
        }
        overlapping.sort_by_key(|(o, _)| *o);

        // Verify the union of the selected chunks covers [start, end) with no
        // gaps.  We walk them in offset order, tracking how far coverage has
        // advanced.
        if overlapping.first().map(|(o, _)| *o).unwrap_or(u32::MAX) > start {
            return None;
        }
        let mut covered_to = start;
        for (o, d) in &overlapping {
            if *o > covered_to {
                return None; // gap before this chunk
            }
            let chunk_end = o + d.len() as u32;
            if chunk_end > covered_to {
                covered_to = chunk_end;
            }
            if covered_to >= end {
                break;
            }
        }
        if covered_to < end {
            return None;
        }

        // Copy the overlapping portion of each chunk into the output buffer.
        let mut buf = vec![0u8; len as usize];
        for (o, d) in &overlapping {
            let chunk_end = o + d.len() as u32;
            let overlap_start = core::cmp::max(*o, start);
            let overlap_end = core::cmp::min(chunk_end, end);
            if overlap_start >= overlap_end {
                continue;
            }
            let dst_start = (overlap_start - start) as usize;
            let dst_end = dst_start + (overlap_end - overlap_start) as usize;
            let src_start = (overlap_start - o) as usize;
            let src_end = src_start + (overlap_end - overlap_start) as usize;
            buf[dst_start..dst_end].copy_from_slice(&d[src_start..src_end]);
        }
        Some(buf)
    }

    /// Read a signed integer of the given byte width from the segment data.
    ///
    /// Returns `0` if the data is not available (LIDATA, gap, or out-of-range).
    pub(super) fn read_addend_at(&self, offset: u32, byte_count: u32) -> i64 {
        for &(chunk_offset, ref chunk) in &self.data_chunks {
            if let OmfDataChunk::Direct(data) = chunk {
                let chunk_end = chunk_offset + data.len() as u32;
                if offset >= chunk_offset && offset + byte_count <= chunk_end {
                    let local = (offset - chunk_offset) as usize;
                    return match byte_count {
                        1 => data[local] as i8 as i64,
                        2 => i16::from_le_bytes([data[local], data[local + 1]]) as i64,
                        4 => i32::from_le_bytes([
                            data[local],
                            data[local + 1],
                            data[local + 2],
                            data[local + 3],
                        ]) as i64,
                        _ => 0,
                    };
                }
            }
        }
        0
    }

    /// Check if any data chunk needs expansion (LIDATA)
    pub fn has_iterated_data(&self) -> bool {
        self.data_chunks
            .iter()
            .any(|(_, chunk)| matches!(chunk, OmfDataChunk::Iterated(_)))
    }
}

/// An OMF segment reference.
#[derive(Debug)]
pub struct OmfSegmentRef<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSegmentRef<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for OmfSegmentRef<'data, 'file, R> {
    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.file.segments[self.index].length as u64
    }

    fn align(&self) -> u64 {
        match self.file.segments[self.index].alignment {
            crate::omf::SegmentAlignment::Byte => 1,
            crate::omf::SegmentAlignment::Word => 2,
            crate::omf::SegmentAlignment::Paragraph => 16,
            crate::omf::SegmentAlignment::Page => 256,
            crate::omf::SegmentAlignment::DWord => 4,
            crate::omf::SegmentAlignment::Page4K => 4096,
            _ => 1,
        }
    }

    fn file_range(&self) -> (u64, u64) {
        (0, 0)
    }

    fn data(&self) -> Result<&'data [u8]> {
        // OMF segments don't have direct file mapping
        Ok(&[])
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(self
            .file
            .get_name(self.file.segments[self.index].name_index))
    }

    fn name(&self) -> Result<Option<&'data str>> {
        let index = self.file.segments[self.index].name_index;
        let name_opt = self.file.get_name(index);
        match name_opt {
            Some(bytes) => Ok(core::str::from_utf8(bytes).ok()),
            None => Ok(None),
        }
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }

    fn permissions(&self) -> Permissions {
        // Derive permissions from the segment's section kind.
        let kind = self.file.segment_section_kind(self.index);
        match kind {
            read::SectionKind::Text => Permissions::new(true, false, true),
            read::SectionKind::ReadOnlyData => Permissions::new(true, false, false),
            _ => Permissions::new(true, true, false),
        }
    }
}

/// An iterator over OMF segments.
#[derive(Debug)]
pub struct OmfSegmentIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSegmentIterator<'data, 'file, R> {
    type Item = OmfSegmentRef<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.segments.len() {
            let segment = OmfSegmentRef {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(segment)
        } else {
            None
        }
    }
}
