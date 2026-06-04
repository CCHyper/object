//! OMF file implementation for the unified read API.

use alloc::vec::Vec;

use crate::read::{
    self, Architecture, ByteString, CodeView, Error, Export, FileFlags, Import,
    NoDynamicRelocationIterator, Object, ObjectKind, ObjectSection, ReadRef, Result, SectionIndex,
    SymbolIndex,
};
use crate::{omf, SubArchitecture};

use super::comdat::{OmfComdatData, OmfComdatSelection};
use super::relocation::OmfFixup;
use super::section::OmfGroup;
use super::segment::OmfDataChunk;
use super::{
    OmfComdat, OmfComdatIterator, OmfSection, OmfSectionIterator, OmfSegment, OmfSegmentIterator,
    OmfSegmentRef, OmfSymbol, OmfSymbolClass, OmfSymbolIterator, OmfSymbolTable,
};

/// An OMF object file.
///
/// This handles both 16-bit and 32-bit OMF variants.
#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data> = &'data [u8]> {
    pub(super) data: R,
    /// The module name from THEADR/LHEADR record
    pub(super) module_name: Option<&'data str>,
    /// Segment definitions
    pub(super) segments: Vec<OmfSegment<'data>>,
    /// All symbols (publics, externals, communals, locals) in occurrence order
    pub(super) symbols: Vec<OmfSymbol<'data>>,
    /// Maps external-name table index (1-based) to SymbolIndex
    pub(super) external_order: Vec<SymbolIndex>,
    /// COMDAT sections
    pub(super) comdats: Vec<OmfComdatData<'data>>,
    /// Name table (LNAMES/LLNAMES)
    pub(super) names: Vec<&'data [u8]>,
    /// Group definitions
    pub(super) groups: Vec<OmfGroup>,
    /// Maps segment 0-based index → SymbolIndex of its synthetic section symbol.
    /// Populated by `create_section_symbols()` after all records are parsed.
    pub(super) segment_symbol_map: Vec<usize>,
    /// True if any segment in this module uses 32-bit addressing (use32 = true).
    pub(super) is_32bit: bool,
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for OmfFile<'data, R> {}

impl<'data, R: ReadRef<'data>> OmfFile<'data, R> {
    /// Parse an OMF file from raw data
    pub fn parse(data: R) -> Result<Self> {
        let mut file = OmfFile {
            data,
            module_name: None,
            segments: Vec::new(),
            symbols: Vec::new(),
            external_order: Vec::new(),
            comdats: Vec::new(),
            names: Vec::new(),
            groups: Vec::new(),
            segment_symbol_map: Vec::new(),
            is_32bit: false,
        };

        file.parse_records()?;
        file.assign_symbol_kinds();
        // Infer PUBDEF symbol sizes from adjacent symbols within each segment.
        // OMF PUBDEF records do not encode symbol sizes; the size of each symbol
        // is the distance to the next symbol in the same segment, or to the end
        // of the segment for the last symbol.
        file.compute_symbol_sizes();
        // OMF is an x86 format; compilers (especially Borland) insert NOP-like
        // padding after `ret`/`jmp` instructions to align the next function.
        // These padding bytes get included in the preceding function's size by
        // compute_symbol_sizes() since it measures adjacent-symbol gaps.  Trim
        // them so disassembly views don't show spurious trailing instructions.
        file.trim_code_alignment_padding();
        // Create one section symbol per segment so consumers (e.g. objdiff)
        // can resolve segment-relative relocations to a symbol target.
        // Must run after assign_symbol_kinds() and compute_symbol_sizes()
        // to avoid interfering with PUBDEF kind/size inference.
        file.create_section_symbols();
        // Detect architecture after all SEGDEF records have been processed.
        file.is_32bit = file.segments.iter().any(|s| s.use32);
        Ok(file)
    }

    /// Merge related OMF sections for a cleaner section tree.
    ///
    /// This performs two transformations:
    /// 1. **COMDAT promotion**: Promotes COMDAT records (inline/linkonce functions)
    ///    to full synthetic segments so disassemblers can see them.
    /// 2. **Same-name merge**: Merges segments with the same (name, class) key
    ///    into a single section. This collapses Watcom's per-function `_TEXT`
    ///    segments and Borland's per-symbol VIRDEF communal segments.
    ///
    /// Call this after `parse()` to enable merging. Symbol offsets, relocations,
    /// line numbers, and section symbols are all adjusted automatically.
    pub fn merge_sections(&mut self) {
        // Promote COMDATs to synthetic segments.
        self.create_comdat_segments();
        // Merge segments with identical (name_index, class_index).
        self.merge_same_name_segments();
        // Re-run dependent post-processing (these overwrite, so safe to re-run).
        self.assign_symbol_kinds();
        self.compute_symbol_sizes();
        self.trim_code_alignment_padding();
        // Rebuild section symbols — first remove any existing ones, then recreate.
        self.symbols.retain(|s| s.class != OmfSymbolClass::Section);
        self.create_section_symbols();
    }

    fn assign_symbol_kinds(&mut self) {
        // Compute kinds for symbols based on their segments
        let kinds: Vec<read::SymbolKind> = self
            .symbols
            .iter()
            .map(|sym| match sym.class {
                OmfSymbolClass::Public | OmfSymbolClass::LocalPublic => {
                    if sym.segment_index > 0 && (sym.segment_index as usize) <= self.segments.len()
                    {
                        let segment_idx = (sym.segment_index - 1) as usize;
                        let section_kind = self.segment_section_kind(segment_idx);
                        Self::symbol_kind_from_section_kind(section_kind)
                    } else {
                        read::SymbolKind::Unknown
                    }
                }
                OmfSymbolClass::Communal | OmfSymbolClass::LocalCommunal => read::SymbolKind::Data,
                _ => read::SymbolKind::Unknown,
            })
            .collect();

        // Apply computed kinds
        for (sym, kind) in self.symbols.iter_mut().zip(kinds) {
            sym.kind = kind;
        }
    }

    /// Infer symbol sizes for PUBDEF/LPUBDEF symbols within each segment.
    ///
    /// OMF PUBDEF records specify a symbol's offset within a segment but not
    /// its size. We infer the size as the distance to the next symbol in the
    /// same segment (sorted by offset), or to the declared segment end for the
    /// last symbol. The result is stored in `communal_size`, which `size()`
    /// already returns, so no change to the `ObjectSymbol` trait impl is needed.
    fn compute_symbol_sizes(&mut self) {
        for seg_idx in 1..=self.segments.len() {
            let seg_length = self.segments[seg_idx - 1].length;

            // Collect indices of PUBDEF/LPUBDEF symbols in this segment.
            let mut sym_indices: Vec<usize> = self
                .symbols
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    s.segment_index as usize == seg_idx
                        && matches!(
                            s.class,
                            OmfSymbolClass::Public | OmfSymbolClass::LocalPublic
                        )
                })
                .map(|(i, _)| i)
                .collect();

            // Sort by offset within the segment.
            sym_indices.sort_by_key(|&i| self.symbols[i].offset);

            // Assign size = distance to next symbol, or to segment end.
            let count = sym_indices.len();
            for k in 0..count {
                let this_offset = self.symbols[sym_indices[k]].offset;
                let next_offset = if k + 1 < count {
                    self.symbols[sym_indices[k + 1]].offset
                } else {
                    seg_length
                };
                self.symbols[sym_indices[k]].communal_size =
                    next_offset.saturating_sub(this_offset);
            }
        }
    }

    /// Trim trailing x86 alignment padding from computed symbol sizes.
    ///
    /// Borland C++ (and some other compilers) align functions to 16-byte
    /// boundaries by inserting NOP-equivalent instructions after `ret` or
    /// `jmp` instructions.  Since `compute_symbol_sizes()` measures the
    /// distance between adjacent PUBDEFs, these padding bytes get included
    /// in the preceding symbol's size.  This method scans the tail of each
    /// public symbol in a CODE segment and removes recognised NOP patterns.
    fn trim_code_alignment_padding(&mut self) {
        // Phase 1: build a set of CODE segment indices (1-based) to limit the
        // per-symbol work below.  Class name "CODE" is how both Borland and
        // Watcom mark executable segments in their OMF output.
        let mut is_code_segment: Vec<bool> = Vec::with_capacity(self.segments.len());
        for seg in &self.segments {
            let is_code = if seg.class_index > 0 {
                self.names
                    .get((seg.class_index - 1) as usize)
                    .copied()
                    .unwrap_or(b"")
                    == b"CODE"
            } else {
                false
            };
            is_code_segment.push(is_code);
        }

        if !is_code_segment.iter().any(|&b| b) {
            return;
        }

        // Phase 2: trim trailing NOP padding from public symbols in CODE
        // segments.  We look up each symbol's byte range via the segment's
        // chunk map, which also works when a segment is split across multiple
        // LEDATA records — the common case for large Borland `_TEXT` segments.
        // Borrowing rules: `get_range_single_chunk` returns a `&'data [u8]`
        // that lives beyond `self.segments`, so the borrow on `self.segments`
        // ends before we touch `self.symbols`.
        let mut updates: Vec<(usize, u32)> = Vec::new();
        for (sym_index, sym) in self.symbols.iter().enumerate() {
            if sym.communal_size == 0 {
                continue;
            }
            if !matches!(
                sym.class,
                OmfSymbolClass::Public | OmfSymbolClass::LocalPublic
            ) {
                continue;
            }
            let seg_0 = match sym.segment_index.checked_sub(1) {
                Some(i) => i as usize,
                None => continue,
            };
            if !is_code_segment.get(seg_0).copied().unwrap_or(false) {
                continue;
            }
            let seg = match self.segments.get(seg_0) {
                Some(s) => s,
                None => continue,
            };
            // Fast path: the symbol's byte range sits inside a single Direct
            // LEDATA chunk (the overwhelming majority of symbols).  Slow path:
            // the range straddles multiple chunks — copy the bytes into a
            // temporary buffer so we can still trim.  Borland's large `_TEXT`
            // segments hit the slow path whenever a function happens to cross
            // a ~1 KiB LEDATA flush boundary.
            let trimmed = if let Some(slice) =
                seg.get_range_single_chunk(sym.offset, sym.communal_size)
            {
                trim_trailing_x86_nops(slice)
            } else if let Some(bytes) =
                seg.copy_range_bytes(sym.offset, sym.communal_size)
            {
                trim_trailing_x86_nops(&bytes)
            } else {
                continue;
            };
            if trimmed > 0 && (trimmed as u32) < sym.communal_size {
                updates.push((sym_index, trimmed as u32));
            }
        }
        for (sym_index, new_size) in updates {
            self.symbols[sym_index].communal_size = new_size;
        }
    }

    /// Create one section symbol per segment, analogous to COFF/ELF section symbols.
    ///
    /// These synthetic symbols have `SymbolKind::Section` and `OmfSymbolClass::Section`.
    /// They serve as relocation targets for segment-relative FIXUPP records so that
    /// consumers (e.g. objdiff) can resolve `RelocationTarget::Symbol` back to a
    /// section without needing special `RelocationTarget::Section` handling.
    fn create_section_symbols(&mut self) {
        self.segment_symbol_map = Vec::with_capacity(self.segments.len());
        for i in 0..self.segments.len() {
            let sym_idx = self.symbols.len();
            let seg_1based = (i + 1) as u16;
            let name_idx = self.segments[i].name_index;
            let name = self.get_name(name_idx).unwrap_or(b"");
            self.segment_symbol_map.push(sym_idx);
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name,
                class: OmfSymbolClass::Section,
                group_index: 0,
                segment_index: seg_1based,
                frame_number: 0,
                offset: 0,
                communal_size: 0,
                type_index: 0,
                kind: read::SymbolKind::Section,
                is_weak: false,
                communal_data_type: 0,
            });
        }
    }

    /// Create a synthetic `OmfSegment` for every COMDAT record that carries
    /// inline data, and link the matching symbol to that segment.
    ///
    /// Watcom (and some Borland) compilers place inline / linkonce functions
    /// inside COMDAT records.  The normal `sections()` iterator only exposes
    /// real SEGDEF-based segments, so objdiff (which only calls `sections()`)
    /// cannot see these functions.  By creating a synthetic segment per COMDAT
    /// we make the code visible to the rest of the toolchain.
    ///
    /// Must be called **before** `assign_symbol_kinds()` so that the updated
    /// `segment_index` on each matched symbol is seen during kind assignment.
    fn create_comdat_segments(&mut self) {
        // ── Re-resolve pass: PUBDEF-after-COMDAT ordering fix ─────────────────
        // `parse_comdat()` resolves `symbol_index` at record-parse time, but
        // when the matching PUBDEF appears *after* the COMDAT in the OBJ file
        // (common in Watcom/Borland objects like DYNAVEC.OBJ), `symbol_index`
        // is left as `None`.  Now that all records have been parsed we can do a
        // second pass and fill in any missing links.
        for i in 0..self.comdats.len() {
            if self.comdats[i].symbol_index.is_none() {
                // name is &'data [u8] — Copy, so this borrow ends before the next.
                let name = self.comdats[i].name;
                let found = self.symbols.iter().position(|s| {
                    s.name == name
                        && matches!(
                            s.class,
                            OmfSymbolClass::Public | OmfSymbolClass::ComdatExternal
                        )
                });
                self.comdats[i].symbol_index = found;
            }
        }

        // Detect the per-file 32-bit flag from existing SEGDEF segments.
        // (file.is_32bit is computed after this function.)
        let any_use32 = self.segments.iter().any(|s| s.use32);

        // Collect everything we need from self.comdats before we mutate self.segments.
        // Use iter_mut() + mem::take() to move relocations without cloning.
        struct Pending<'d> {
            name: &'d [u8],
            data_slices: Vec<&'d [u8]>,
            symbol_idx: Option<usize>,
            relocations: Vec<OmfFixup>,
            line_numbers: Vec<(u16, u32)>,
        }

        let pendings: Vec<Pending<'data>> = self
            .comdats
            .iter_mut()
            .filter(|c| !c.data_slices.is_empty()) // only COMDATs with actual inline code
            .map(|c| Pending {
                name: c.name,
                data_slices: core::mem::take(&mut c.data_slices),
                symbol_idx: c.symbol_index,
                relocations: core::mem::take(&mut c.relocations),
                line_numbers: core::mem::take(&mut c.line_numbers),
            })
            .collect();

        if pendings.is_empty() {
            return;
        }

        // All inline-COMDAT functions go into a single "COMDAT" section so that the
        // GUI shows one grouped tree node instead of one expand-tree entry per symbol.
        // Pack function bodies sequentially; symbols get their correct offsets.
        //
        // "COMDAT" is a synthetic name — push it to the names table.  A &'static [u8]
        // satisfies &'data [u8] because 'static outlives every 'data lifetime.
        let comdat_name_idx = (self.names.len() + 1) as u16;
        self.names.push(b"COMDAT");

        let comdat_seg_1based = (self.segments.len() + 1) as u16;

        let mut data_chunks: Vec<(u32, OmfDataChunk<'data>)> = Vec::new();
        // (symbol_idx, name, offset_in_segment, body_len)
        let mut sym_entries: Vec<(Option<usize>, &'data [u8], u32, u32)> = Vec::new();
        let mut merged_relocations: Vec<OmfFixup> = Vec::new();
        let mut merged_line_numbers: Vec<(u16, u32)> = Vec::new();
        let mut current_offset: u32 = 0;

        for pending in pendings {
            let body_len: u32 = pending.data_slices.iter().map(|s| s.len() as u32).sum();
            let sym_offset = current_offset;
            for slice in &pending.data_slices {
                data_chunks.push((current_offset, OmfDataChunk::Direct(slice)));
                current_offset += slice.len() as u32;
            }
            sym_entries.push((pending.symbol_idx, pending.name, sym_offset, body_len));

            // Adjust each COMDAT fixup offset by the packed position and merge.
            for mut fixup in pending.relocations {
                fixup.offset += sym_offset;
                merged_relocations.push(fixup);
            }

            // Adjust LINSYM line number offsets by the packed position and merge.
            for (line, code_offset) in pending.line_numbers {
                merged_line_numbers.push((line, code_offset + sym_offset));
            }
        }

        self.segments.push(OmfSegment {
            name_index: comdat_name_idx,
            class_index: 0,
            overlay_index: 0,
            alignment: omf::SegmentAlignment::Byte,
            combination: omf::SegmentCombination::Private,
            use32: any_use32,
            length: current_offset,
            data_chunks,
            relocations: merged_relocations,
            is_comdat: true,
            is_communal: false,
            line_numbers: merged_line_numbers,
        });

        // Point each COMDAT's symbol at the merged segment with its packed offset.
        // If no matching symbol exists (DYNAVEC.OBJ style), synthesise a Public one.
        for (symbol_idx, name, offset, body_len) in sym_entries {
            if let Some(sym_idx) = symbol_idx {
                if let Some(sym) = self.symbols.get_mut(sym_idx) {
                    sym.segment_index = comdat_seg_1based;
                    sym.offset = offset;
                    sym.communal_size = body_len;
                }
            } else {
                let sym_idx = self.symbols.len();
                self.symbols.push(OmfSymbol {
                    symbol_index: sym_idx,
                    name,
                    class: OmfSymbolClass::Public,
                    group_index: 0,
                    segment_index: comdat_seg_1based,
                    frame_number: 0,
                    offset,
                    communal_size: body_len,
                    type_index: 0,
                    kind: read::SymbolKind::Unknown, // fixed by assign_symbol_kinds()
                    is_weak: false,
                    communal_data_type: 0,
                });
            }
        }
    }

    /// Merge segments that share the same (name_index, class_index) into a
    /// single segment, adjusting all cross-references.
    ///
    /// ## Why this is needed
    ///
    /// Watcom's `-d2` (full debug) build model emits a **separate SEGDEF for
    /// every function**, all sharing the same name (`_TEXT`) and class (`CODE`).
    /// BUILDING.OBJ, for example, has 77 individual `_TEXT`/`CODE` segments.
    /// The linker normally concatenates these into one `.text` section, but at
    /// the object-file level they appear as dozens of individual sections.
    /// This confuses tools that display per-section trees (like objdiff) —
    /// each function shows up under its own `_TEXT` node rather than all
    /// appearing under a single `_TEXT` section.
    ///
    /// This method replicates what the linker would do: group segments by
    /// `(name_index, class_index)` and merge groups with more than one member
    /// into a single segment.  Symbol offsets, relocation targets/displacements,
    /// line numbers, group references, and COMDAT segment indices are all
    /// adjusted to reflect the new segment layout.
    ///
    /// The approach mirrors `create_comdat_segments()` which already performs
    /// a similar merge for inline COMDAT functions.
    fn merge_same_name_segments(&mut self) {
        if self.segments.len() <= 1 {
            return;
        }

        // ── Step 1: Group segments by (name_index, class_index). ────────────
        // Skip unnamed segments (name_index == 0) and synthetic COMDAT segments
        // — these should remain as individual sections.

        // groups[i] = Vec of 0-based segment indices sharing the same key.
        // group_keys[i] = (name_index, class_index) for that group.
        let mut group_keys: Vec<(u16, u16)> = Vec::new();
        let mut groups: Vec<Vec<usize>> = Vec::new();
        // Maps old 0-based segment index → group index (or usize::MAX if ungrouped).
        let mut seg_to_group: Vec<usize> = Vec::with_capacity(self.segments.len());

        for (i, seg) in self.segments.iter().enumerate() {
            if seg.name_index == 0 || seg.is_comdat {
                // Unnamed or synthetic COMDAT — keep as standalone.
                seg_to_group.push(usize::MAX);
                continue;
            }
            let key = (seg.name_index, seg.class_index);
            let gidx = group_keys.iter().position(|k| *k == key);
            match gidx {
                Some(gidx) => {
                    groups[gidx].push(i);
                    seg_to_group.push(gidx);
                }
                None => {
                    seg_to_group.push(group_keys.len());
                    group_keys.push(key);
                    groups.push(vec![i]);
                }
            }
        }

        // If no group has more than one member there is nothing to merge.
        if !groups.iter().any(|g| g.len() > 1) {
            return;
        }

        // ── Step 2: Build remap table and new segments Vec. ─────────────────
        // remap[old_0based] = (new_0based, offset_within_merged_segment)
        let old_count = self.segments.len();
        let mut remap: Vec<(usize, u32)> = vec![(0, 0); old_count];
        let mut new_segments: Vec<OmfSegment<'data>> = Vec::new();

        // Helper: convert SegmentAlignment → byte value for comparison.
        let align_bytes = |a: omf::SegmentAlignment| -> u64 {
            match a {
                omf::SegmentAlignment::Byte => 1,
                omf::SegmentAlignment::Word => 2,
                omf::SegmentAlignment::DWord => 4,
                omf::SegmentAlignment::Paragraph => 16,
                omf::SegmentAlignment::Page => 256,
                omf::SegmentAlignment::Page4K => 4096,
                _ => 1,
            }
        };

        // Process grouped (named) segments first, preserving group order.
        for group in &groups {
            let new_idx = new_segments.len();

            if group.len() == 1 {
                // Singleton — move directly, no merging needed.
                let old_idx = group[0];
                remap[old_idx] = (new_idx, 0);
                // Take the segment out (replace with a dummy that will be discarded).
                let seg = core::mem::replace(&mut self.segments[old_idx], dummy_segment());
                new_segments.push(seg);
            } else {
                // Multi-member group — merge into one segment.
                // Capture properties from the first segment before the loop
                // replaces it with a dummy via core::mem::replace().
                let first = group[0];
                let merged_name_index = self.segments[first].name_index;
                let merged_class_index = self.segments[first].class_index;
                let merged_combination = self.segments[first].combination;
                let merged_use32 = self.segments[first].use32;

                let mut merged_length: u32 = 0;
                let mut merged_data: Vec<(u32, OmfDataChunk<'data>)> = Vec::new();
                let mut merged_relocs: Vec<OmfFixup> = Vec::new();
                let mut merged_lines: Vec<(u16, u32)> = Vec::new();
                let mut best_align = self.segments[first].alignment;

                for &old_idx in group {
                    let seg = core::mem::replace(&mut self.segments[old_idx], dummy_segment());
                    let base = merged_length;
                    remap[old_idx] = (new_idx, base);

                    // Merge data chunks with offset adjustment.
                    for (chunk_off, chunk) in seg.data_chunks {
                        merged_data.push((chunk_off + base, chunk));
                    }

                    // Merge relocations — adjust the fixup offset (location within
                    // the source segment) by the packed position.
                    for mut fixup in seg.relocations {
                        fixup.offset += base;
                        merged_relocs.push(fixup);
                    }

                    // Merge line numbers with offset adjustment.
                    for (line, off) in seg.line_numbers {
                        merged_lines.push((line, off + base));
                    }

                    // Track strictest alignment.
                    if align_bytes(seg.alignment) > align_bytes(best_align) {
                        best_align = seg.alignment;
                    }

                    merged_length += seg.length;
                }

                new_segments.push(OmfSegment {
                    name_index: merged_name_index,
                    class_index: merged_class_index,
                    overlay_index: 0,
                    alignment: best_align,
                    combination: merged_combination,
                    use32: merged_use32,
                    length: merged_length,
                    data_chunks: merged_data,
                    relocations: merged_relocs,
                    is_comdat: false,
                    is_communal: false,
                    line_numbers: merged_lines,
                });
            }
        }

        // Append ungrouped segments (unnamed or COMDAT) in their original order.
        for (old_idx, &gidx) in seg_to_group.iter().enumerate() {
            if gidx == usize::MAX {
                let new_idx = new_segments.len();
                remap[old_idx] = (new_idx, 0);
                let seg = core::mem::replace(&mut self.segments[old_idx], dummy_segment());
                new_segments.push(seg);
            }
        }

        // ── Step 3: Remap all symbol segment references. ────────────────────
        for sym in &mut self.symbols {
            if sym.segment_index > 0 && (sym.segment_index as usize) <= old_count {
                let old_idx = (sym.segment_index as usize) - 1;
                let (new_idx, merge_offset) = remap[old_idx];
                sym.segment_index = (new_idx + 1) as u16;
                sym.offset += merge_offset;
            }
        }

        // ── Step 4: Remap relocation targets across ALL segments. ───────────
        // A fixup in segment A may target segment B (via target_method =
        // SegmentIndex).  If B was merged, we must:
        //   - Remap target_index to the merged segment's new 1-based index.
        //   - Add the merge offset to target_displacement so the resolved
        //     address points to the correct position within the merged segment.
        // Frame indices (frame_method = SegmentIndex) are remapped similarly
        // but do not carry a displacement.
        for seg in &mut new_segments {
            for fixup in &mut seg.relocations {
                // Remap target.
                if matches!(fixup.target_method, TargetMethod::SegmentIndex)
                    && fixup.target_index > 0
                    && (fixup.target_index as usize) <= old_count
                {
                    let old_idx = (fixup.target_index as usize) - 1;
                    let (new_idx, merge_offset) = remap[old_idx];
                    fixup.target_index = (new_idx + 1) as u16;
                    fixup.target_displacement += merge_offset;
                }

                // Remap frame.
                if matches!(fixup.frame_method, FrameMethod::SegmentIndex)
                    && fixup.frame_index > 0
                    && (fixup.frame_index as usize) <= old_count
                {
                    let old_idx = (fixup.frame_index as usize) - 1;
                    let (new_idx, _) = remap[old_idx];
                    fixup.frame_index = (new_idx + 1) as u16;
                }
            }
        }

        // ── Step 5: Remap group segment references. ─────────────────────────
        for group in &mut self.groups {
            for seg_idx in &mut group.segments {
                if *seg_idx > 0 && (*seg_idx as usize) <= old_count {
                    let old_idx = (*seg_idx as usize) - 1;
                    let (new_idx, _) = remap[old_idx];
                    *seg_idx = (new_idx + 1) as u16;
                }
            }
            // Deduplicate: after remapping, multiple old segments may map to
            // the same merged segment index.
            group.segments.dedup();
        }

        // ── Step 6: Remap COMDAT segment references. ────────────────────────
        for comdat in &mut self.comdats {
            if comdat.segment_index > 0 && (comdat.segment_index as usize) <= old_count {
                let old_idx = (comdat.segment_index as usize) - 1;
                let (new_idx, _) = remap[old_idx];
                comdat.segment_index = (new_idx + 1) as u16;
            }
        }

        // ── Step 7: Replace the segments Vec. ───────────────────────────────
        self.segments = new_segments;
    }

    fn symbol_kind_from_section_kind(section_kind: read::SectionKind) -> read::SymbolKind {
        match section_kind {
            read::SectionKind::Text => read::SymbolKind::Text,
            read::SectionKind::Data | read::SectionKind::ReadOnlyData => read::SymbolKind::Data,
            read::SectionKind::UninitializedData => read::SymbolKind::Data,
            _ => read::SymbolKind::Unknown,
        }
    }

    /// Get the section kind for a segment
    pub(super) fn segment_section_kind(&self, segment_index: usize) -> read::SectionKind {
        let Some(segment) = self.segments.get(segment_index) else {
            return read::SectionKind::Unknown;
        };

        // Synthetic COMDAT segments always contain executable code.
        if segment.is_comdat {
            return read::SectionKind::Text;
        }

        let segment_name = self.get_name(segment.name_index).unwrap_or_default();
        let class_name = self.get_name(segment.class_index).unwrap_or_default();

        // Reserved names for debug sections (case-sensitive: $ prefix is exact).
        if segment_name.starts_with(b"$$") {
            return read::SectionKind::Debug;
        }

        // Uppercase copies for case-insensitive matching.
        // Borland and Watcom compilers sometimes emit lowercase class names (e.g. "code").
        let seg_upper: Vec<u8> = segment_name.iter().map(|b| b.to_ascii_uppercase()).collect();
        let cls_upper: Vec<u8> = class_name.iter().map(|b| b.to_ascii_uppercase()).collect();

        // Substring matches for common class names (case-insensitive).
        if cls_upper.windows(4).any(|w| w == b"CODE") {
            return read::SectionKind::Text;
        } else if cls_upper.windows(4).any(|w| w == b"DATA") {
            if seg_upper.windows(5).any(|w| w == b"CONST") {
                return read::SectionKind::ReadOnlyData;
            } else {
                return read::SectionKind::Data;
            }
        } else if cls_upper.windows(3).any(|w| w == b"BSS")
            || cls_upper.windows(5).any(|w| w == b"STACK")
        {
            return read::SectionKind::UninitializedData;
        } else if cls_upper.starts_with(b"DEB") {
            return read::SectionKind::Debug;
        } else if cls_upper == b"COMMON" {
            return read::SectionKind::Common;
        }

        read::SectionKind::Unknown
    }

    fn parse_records(&mut self) -> Result<()> {
        let mut current_segment: Option<usize> = None;
        let mut current_data_offset: Option<u32> = None;
        // Index of the most recently parsed COMDAT (for routing FIXUPP records).
        let mut current_comdat: Option<usize> = None;

        // Thread storage for FIXUPP parsing
        let mut frame_threads: [Option<ThreadDef>; 4] = [None; 4];
        let mut target_threads: [Option<ThreadDef>; 4] = [None; 4];

        let mut offset = 0;
        while let Ok(record_header) = self.data.read_at::<omf::RecordHeader>(offset) {
            let record_type = record_header.record_type;
            let record_length = record_header.length.get(crate::endian::LittleEndian);
            let record_data = self
                .data
                .read_bytes_at(offset, record_length as u64 + 3)
                .map_err(|_| Error("Truncated OMF record data"))?;

            if offset == 0
                && !matches!(
                    record_type,
                    omf::record_type::THEADR | omf::record_type::LHEADR
                )
            {
                return Err(Error(
                    "Invalid OMF file: first record must be THEADR or LHEADR",
                ));
            }

            // Verify checksum. Some Borland/Watcom tools write a non-zero but
            // incorrect checksum byte, so a mismatch is treated as a soft skip
            // rather than a fatal error: we advance past the record and continue.
            if !omf::verify_checksum(record_data) {
                offset += record_length as u64 + 3;
                continue;
            }

            // OMF record_length includes the checksum byte; minimum valid value is 1.
            if record_length < 1 {
                return Err(Error(
                    "OMF record length must be at least 1 (checksum byte required)",
                ));
            }

            // Exclude the 3-byte header and the trailing checksum byte.
            // record_data = [type(1)][len_lo(1)][len_hi(1)][content(record_length-1)][checksum(1)]
            // inner_data covers only the content bytes [content(record_length-1)]
            let inner_data = &record_data[3..2 + record_length as usize];

            // Process record based on type
            match record_type {
                omf::record_type::THEADR | omf::record_type::LHEADR => {
                    self.parse_header(inner_data)?;
                }
                omf::record_type::LNAMES | omf::record_type::LLNAMES => {
                    self.parse_names(inner_data)?;
                }
                omf::record_type::SEGDEF | omf::record_type::SEGDEF32 => {
                    self.parse_segdef(inner_data, record_type == omf::record_type::SEGDEF32)?;
                }
                omf::record_type::GRPDEF => {
                    self.parse_grpdef(inner_data)?;
                }
                omf::record_type::PUBDEF | omf::record_type::PUBDEF32 => {
                    self.parse_pubdef(
                        inner_data,
                        record_type == omf::record_type::PUBDEF32,
                        OmfSymbolClass::Public,
                    )?;
                }
                omf::record_type::LPUBDEF | omf::record_type::LPUBDEF32 => {
                    self.parse_pubdef(
                        inner_data,
                        record_type == omf::record_type::LPUBDEF32,
                        OmfSymbolClass::LocalPublic,
                    )?;
                }
                omf::record_type::EXTDEF => {
                    self.parse_extdef(inner_data, OmfSymbolClass::External)?;
                }
                omf::record_type::LEXTDEF | omf::record_type::LEXTDEF32 => {
                    self.parse_extdef(inner_data, OmfSymbolClass::LocalExternal)?;
                }
                omf::record_type::CEXTDEF => {
                    self.parse_extdef(inner_data, OmfSymbolClass::ComdatExternal)?;
                }
                omf::record_type::COMDEF => {
                    self.parse_comdef(inner_data, OmfSymbolClass::Communal)?;
                }
                omf::record_type::LCOMDEF => {
                    self.parse_comdef(inner_data, OmfSymbolClass::LocalCommunal)?;
                }
                omf::record_type::COMDAT | omf::record_type::COMDAT32 => {
                    self.parse_comdat(inner_data, record_type == omf::record_type::COMDAT32)?;
                    // A FIXUPP following COMDAT patches the COMDAT's inline data.
                    // Track which COMDAT was just parsed so the next FIXUPP stores
                    // relocations on it (offsets relative to the COMDAT body).
                    current_comdat = Some(self.comdats.len() - 1);
                    current_segment = None;
                    current_data_offset = None;
                }
                omf::record_type::COMENT => {
                    self.parse_comment(inner_data)?;
                }
                omf::record_type::LEDATA | omf::record_type::LEDATA32 => {
                    let (seg_idx, offset) =
                        self.parse_ledata(inner_data, record_type == omf::record_type::LEDATA32)?;
                    current_segment = Some(seg_idx);
                    current_data_offset = Some(offset);
                    current_comdat = None;
                }
                omf::record_type::LIDATA | omf::record_type::LIDATA32 => {
                    let (seg_idx, offset) =
                        self.parse_lidata(inner_data, record_type == omf::record_type::LIDATA32)?;
                    current_segment = Some(seg_idx);
                    current_data_offset = Some(offset);
                    current_comdat = None;
                }
                omf::record_type::FIXUPP | omf::record_type::FIXUPP32 => {
                    let is_32bit_fixupp = record_type == omf::record_type::FIXUPP32;
                    if let (Some(seg_idx), Some(data_offset)) =
                        (current_segment, current_data_offset)
                    {
                        self.parse_fixupp(
                            inner_data,
                            is_32bit_fixupp,
                            seg_idx,
                            data_offset,
                            &mut frame_threads,
                            &mut target_threads,
                        )?;
                    } else if let Some(comdat_idx) = current_comdat {
                        // FIXUPP follows a COMDAT — parse fixups with data_offset=0
                        // (offsets are relative to the start of the COMDAT body).
                        let reloc_start = self.comdats[comdat_idx].relocations.len();
                        parse_fixupp_records(
                            inner_data,
                            is_32bit_fixupp,
                            0,
                            &mut frame_threads,
                            &mut target_threads,
                            &mut self.comdats[comdat_idx].relocations,
                        )?;
                        // Resolve Borland communal segment refs in COMDAT fixups.
                        self.resolve_comdat_fixupp_communal_refs(
                            comdat_idx,
                            reloc_start,
                        )?;
                    }
                }
                omf::record_type::ALIAS => {
                    self.parse_alias(inner_data)?;
                }
                omf::record_type::LINNUM | omf::record_type::LINNUM32 => {
                    self.parse_linnum(
                        inner_data,
                        record_type == omf::record_type::LINNUM32,
                    )?;
                }
                omf::record_type::LINSYM | omf::record_type::LINSYM32 => {
                    self.parse_linsym(
                        inner_data,
                        record_type == omf::record_type::LINSYM32,
                    )?;
                }
                omf::record_type::MODEND | omf::record_type::MODEND32 => {
                    // End of module
                    break;
                }
                _ => {
                    // Skip unknown record types
                }
            }

            offset += record_length as u64 + 3;
        }

        if offset == 0 {
            return Err(Error("No OMF records found"));
        }

        Ok(())
    }

    fn parse_header(&mut self, data: &'data [u8]) -> Result<()> {
        if let Some((name, _)) = read_counted_string(data) {
            self.module_name = core::str::from_utf8(name).ok();
        }
        Ok(())
    }

    fn parse_names(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            if let Some((name, size)) = read_counted_string(&data[offset..]) {
                self.names.push(name);
                offset += size;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_segdef(&mut self, data: &'data [u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Parse ACBP byte
        if offset >= data.len() {
            return Err(Error("Truncated SEGDEF record"));
        }
        let acbp = data[offset];
        offset += 1;

        let alignment = match (acbp >> 5) & 0x07 {
            0 => omf::SegmentAlignment::Absolute,
            1 => omf::SegmentAlignment::Byte,
            2 => omf::SegmentAlignment::Word,
            3 => omf::SegmentAlignment::Paragraph,
            4 => omf::SegmentAlignment::Page,
            5 => omf::SegmentAlignment::DWord,
            6 => omf::SegmentAlignment::Page4K,
            // Value 7 is reserved; treat as byte alignment (safe fallback for Watcom-era tools).
            _ => omf::SegmentAlignment::Byte,
        };

        let combination = match (acbp >> 2) & 0x07 {
            0 => omf::SegmentCombination::Private,
            // Values 1/3/4 are old-toolchain aliases for Public (old MASM, Borland).
            1..=4 => omf::SegmentCombination::Public,
            5 => omf::SegmentCombination::Stack,
            6 => omf::SegmentCombination::Common,
            // Value 7 is reserved; treat as Private (safe fallback for Watcom-era tools).
            _ => omf::SegmentCombination::Private,
        };

        let use32 = (acbp & 0x01) != 0;
        // B-bit (bit 1): when set, a stored length of 0 means 65536 bytes (full 64KB segment).
        // This is common in 16-bit Borland/Watcom code/data segments.
        let big = (acbp & 0x02) != 0;

        // Skip frame number and offset for absolute segments.
        // Absolute segments have: frame_number(u16) + segment_offset(u8)
        if alignment == omf::SegmentAlignment::Absolute {
            if offset + 3 > data.len() {
                return Err(Error(
                    "Truncated SEGDEF record: missing absolute segment fields",
                ));
            }
            offset += 3; // frame (2) + offset (1)
        }

        // Parse segment length.
        // The field width is determined solely by the *record type*:
        //   SEGDEF  (0x98) → 2-byte length
        //   SEGDEF32(0x99) → 4-byte length
        // The ACBP D-bit (use32) controls 32-bit addressing mode for LEDATA
        // records and must NOT affect the segment-length field width here.
        let length = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            length
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            // B-bit: stored 0 means the segment occupies a full 64KB paragraph.
            if big && length == 0 { 0x10000 } else { length }
        };

        // Parse segment name index
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment name index"))?;
        offset += size;

        // Parse class name index
        let (class_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid class name index"))?;
        offset += size;

        // Parse overlay name index
        let (overlay_index, _) =
            read_index(&data[offset..]).ok_or(Error("Invalid overlay name index"))?;

        self.segments.push(OmfSegment {
            name_index,
            class_index,
            overlay_index,
            alignment,
            combination,
            use32,
            length,
            data_chunks: Vec::new(),
            relocations: Vec::new(),
            is_comdat: false,
            is_communal: false,
            line_numbers: Vec::new(),
        });

        Ok(())
    }

    fn parse_grpdef(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;

        // Parse group name index
        let (name_index, size) = read_index(data).ok_or(Error("Invalid group name index"))?;
        offset += size;

        let mut segments = Vec::new();

        // Parse segment indices
        while offset < data.len() {
            if data[offset] == 0xFF {
                // Segment index follows
                offset += 1;
                let (seg_index, size) =
                    read_index(&data[offset..]).ok_or(Error("Invalid segment index in group"))?;
                offset += size;
                segments.push(seg_index);
            } else {
                break;
            }
        }

        self.groups.push(OmfGroup {
            name_index,
            segments,
        });

        Ok(())
    }

    fn parse_pubdef(
        &mut self,
        data: &'data [u8],
        is_32bit: bool,
        class: OmfSymbolClass,
    ) -> Result<()> {
        let mut offset = 0;

        // Parse group index
        let (group_index, size) = read_index(data).ok_or(Error("Invalid group index"))?;
        offset += size;

        // Parse segment index
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index"))?;
        offset += size;

        // Resolve communal segment reference if present.
        let resolved_segment_index = if segment_index > 0x4000 {
            let seg_0 = self.resolve_communal_segment(segment_index - 0x4000)?;
            (seg_0 + 1) as u16
        } else {
            segment_index
        };

        // Read frame number if segment index is 0 (for absolute symbols)
        let frame_number = if segment_index == 0 {
            if offset + 2 > data.len() {
                return Err(Error("Invalid frame number in PUBDEF"));
            }
            let frame = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            frame
        } else {
            0
        };

        // Parse public definitions
        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse offset
            let pub_offset = if is_32bit {
                if offset + 4 > data.len() {
                    break;
                }
                let off = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                off
            } else {
                if offset + 2 > data.len() {
                    break;
                }
                let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                offset += 2;
                off
            };

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in PUBDEF/LPUBDEF record"))?;
            offset += size;

            self.symbols.push(OmfSymbol {
                symbol_index: self.symbols.len(),
                name,
                class,
                group_index,
                segment_index: resolved_segment_index,
                frame_number,
                offset: pub_offset,
                communal_size: 0,
                type_index,
                kind: read::SymbolKind::Unknown, // Will be computed later
                is_weak: false,
                communal_data_type: 0,
            });
        }

        Ok(())
    }

    /// Parse a LINNUM or LINNUM32 record.
    ///
    /// Format: group_index, segment_index, then repeating (line_number u16, offset u16/u32).
    fn parse_linnum(&mut self, data: &[u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Group index (not used but must be consumed).
        let (_group_index, size) =
            read_index(data).ok_or(Error("Invalid group index in LINNUM record"))?;
        offset += size;

        // Segment index (1-based).
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index in LINNUM record"))?;
        offset += size;

        if segment_index == 0 || segment_index as usize > self.segments.len() {
            return Ok(()); // Invalid or out-of-range segment; skip silently.
        }
        let seg_idx = (segment_index - 1) as usize;

        // Parse repeating (line_number, segment_offset) pairs.
        while offset < data.len() {
            if offset + 2 > data.len() {
                break;
            }
            let line = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            let seg_offset = if is_32bit {
                if offset + 4 > data.len() {
                    break;
                }
                let v = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                v
            } else {
                if offset + 2 > data.len() {
                    break;
                }
                let v = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                offset += 2;
                v
            };

            self.segments[seg_idx].line_numbers.push((line, seg_offset));
        }

        Ok(())
    }

    /// Parse a LINSYM/LINSYM32 record and store line numbers on the matching COMDAT.
    fn parse_linsym(&mut self, data: &[u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Flags byte (reserved, must be consumed).
        if offset >= data.len() {
            return Ok(());
        }
        let _flags = data[offset];
        offset += 1;

        // Public name index — 1-based LNAMES index identifying the COMDAT symbol.
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid name index in LINSYM record"))?;
        offset += size;

        // Find the matching COMDAT by name_index.
        let comdat_idx = self
            .comdats
            .iter()
            .rposition(|c| c.name_index == name_index);
        let Some(comdat_idx) = comdat_idx else {
            return Ok(()); // No matching COMDAT; skip silently.
        };

        // Parse repeating (line_number, code_offset) pairs.
        while offset < data.len() {
            if offset + 2 > data.len() {
                break;
            }
            let line = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            let code_offset = if is_32bit {
                if offset + 4 > data.len() {
                    break;
                }
                let v = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                v
            } else {
                if offset + 2 > data.len() {
                    break;
                }
                let v = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                offset += 2;
                v
            };

            self.comdats[comdat_idx]
                .line_numbers
                .push((line, code_offset));
        }

        Ok(())
    }

    fn parse_extdef(&mut self, data: &'data [u8], class: OmfSymbolClass) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in EXTDEF/LEXTDEF/CEXTDEF record"))?;
            offset += size;

            let sym_idx = self.symbols.len();
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name,
                class,
                group_index: 0,
                segment_index: 0,
                frame_number: 0,
                offset: 0,
                communal_size: 0,
                type_index,
                kind: read::SymbolKind::Unknown,
                is_weak: false,
                communal_data_type: 0,
            });

            // Add to external_order for symbols that contribute to external-name table
            self.external_order.push(read::SymbolIndex(sym_idx));
        }

        Ok(())
    }

    fn parse_comdef(&mut self, data: &'data [u8], class: OmfSymbolClass) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in COMDEF/LCOMDEF record"))?;
            offset += size;

            // Parse data type and communal length
            if offset >= data.len() {
                break;
            }
            let data_type = data[offset];
            offset += 1;

            let communal_length = match data_type {
                0x01..=0x5F => {
                    // VIRDEF (Borland extension): data_type is a 1-based segment
                    // index referencing a SEGDEF (e.g. 1 = _TEXT, 2 = _DATA).
                    // The communal is appended to that segment if instantiated.
                    // Format is like NEAR COMDEF — a single encoded length follows.
                    let (size_val, size_bytes) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid size in VIRDEF COMDEF"))?;
                    offset += size_bytes;
                    size_val
                }
                0x61 => {
                    // FAR data - number of elements followed by element size
                    let (num_elements, size1) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid number of elements in FAR COMDEF"))?;
                    offset += size1;
                    let (element_size, size2) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid element size in FAR COMDEF"))?;
                    offset += size2;
                    num_elements * element_size
                }
                0x62 => {
                    // NEAR data - size in bytes
                    let (size_val, size_bytes) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid size in NEAR COMDEF"))?;
                    offset += size_bytes;
                    size_val
                }
                _ => 0,
            };

            let sym_idx = self.symbols.len();
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name,
                class,
                group_index: 0,
                segment_index: 0,
                frame_number: 0,
                offset: 0,
                communal_size: communal_length,
                type_index,
                kind: read::SymbolKind::Data,
                is_weak: false,
                communal_data_type: data_type,
            });

            // Add to external_order for symbols that contribute to external-name table
            self.external_order.push(read::SymbolIndex(sym_idx));
        }

        Ok(())
    }

    fn parse_comdat(&mut self, data: &'data [u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Parse flags byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let flags = data[offset];
        offset += 1;

        let is_continuation = (flags & 0x02) != 0;

        // Parse attributes byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let attributes = data[offset];
        offset += 1;

        if is_continuation {
            // Continuation record: after flags + attributes, everything is data.
            // Append to the most recent COMDAT entry.
            let comdat_data = &data[offset..];
            if let Some(last) = self.comdats.last_mut() {
                if !comdat_data.is_empty() {
                    last.data_slices.push(comdat_data);
                }
            }
            return Ok(());
        }

        // Extract selection criteria from high nibble of attributes
        let selection = match (attributes >> 4) & 0x0F {
            0x00 => OmfComdatSelection::Explicit,   // No match
            0x01 => OmfComdatSelection::UseAny,     // Pick any
            0x02 => OmfComdatSelection::SameSize,   // Same size
            0x03 => OmfComdatSelection::ExactMatch, // Exact match
            _ => OmfComdatSelection::UseAny,
        };

        // Extract allocation type from low nibble of attributes
        let allocation_type = attributes & 0x0F;

        // Parse align/segment index field
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid COMDAT segment index"))?;
        offset += size;

        // Determine alignment - if segment index is 0-7, it's actually an alignment value
        let alignment = if segment_index <= 7 {
            match segment_index {
                0 => omf::SegmentAlignment::Absolute, // Use value from SEGDEF
                1 => omf::SegmentAlignment::Byte,
                2 => omf::SegmentAlignment::Word,
                3 => omf::SegmentAlignment::Paragraph,
                4 => omf::SegmentAlignment::Page,
                5 => omf::SegmentAlignment::DWord,
                6 => omf::SegmentAlignment::Page4K,
                _ => omf::SegmentAlignment::Byte,
            }
        } else {
            omf::SegmentAlignment::Byte // Default alignment
        };

        // Parse data offset
        let _data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated COMDAT record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated COMDAT record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // Parse type index
        let (_type_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid type index in COMDAT record"))?;
        offset += size;

        // Parse public base (only if allocation type is 0x00 - Explicit)
        if allocation_type == 0x00 {
            // Has public base (Base Group, Base Segment, Base Frame)
            let (_group_index, size) =
                read_index(&data[offset..]).ok_or(Error("Invalid group index in COMDAT record"))?;
            offset += size;
            let (_seg_idx, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid segment index in COMDAT record"))?;
            offset += size;
            if _seg_idx == 0 {
                if offset + 2 <= data.len() {
                    offset += 2; // Skip frame number
                }
            }
        }

        // Parse public name - this is an index into LNAMES
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid name index in COMDAT record"))?;
        offset += size;

        // Look up the name from the names table
        let name = name_index
            .checked_sub(1)
            .and_then(|i| self.names.get(i as usize).copied())
            .unwrap_or(b"");

        // Find the matching public or COMDAT-external symbol for this COMDAT.
        let symbol_index = self.symbols.iter().position(|s| {
            s.name == name
                && matches!(
                    s.class,
                    OmfSymbolClass::Public | OmfSymbolClass::ComdatExternal
                )
        });

        // Remaining data is the COMDAT content
        let comdat_data = &data[offset..];

        let mut data_slices = Vec::new();
        if !comdat_data.is_empty() {
            data_slices.push(comdat_data);
        }

        self.comdats.push(OmfComdatData {
            name,
            name_index,
            segment_index,
            selection,
            alignment,
            data_slices,
            symbol_index,
            relocations: Vec::new(),
            line_numbers: Vec::new(),
        });

        Ok(())
    }

    fn parse_comment(&mut self, data: &'data [u8]) -> Result<()> {
        if data.len() < 2 {
            return Ok(()); // Ignore truncated comments
        }

        let _comment_type = data[0]; // Usually 0x00 for non-purge, 0x40 for purge
        let comment_class = data[1];
        let payload = &data[2..];

        match comment_class {
            // WKEXT (0xA7) and LZEXT (0xA8): Watcom weak/lazy external records.
            // Payload is a list of (weak_ext_index, default_ext_index) index pairs,
            // each index encoded as a variable-length OMF index (1- or 2-byte).
            // We mark the weak symbol as weak; the default resolution is advisory only.
            0xA7 | 0xA8 => {
                let mut offset = 0;
                while offset < payload.len() {
                    let (weak_idx, sz) =
                        match read_index(&payload[offset..]) {
                            Some(v) => v,
                            None => break,
                        };
                    offset += sz;

                    // Consume the default-resolution index (not stored, just skip).
                    let (_, sz) = match read_index(&payload[offset..]) {
                        Some(v) => v,
                        None => break,
                    };
                    offset += sz;

                    // Resolve the weak external index to a symbol and mark it.
                    if let Some(sym) = self
                        .external_order
                        .get(weak_idx.checked_sub(1).unwrap_or(u16::MAX) as usize)
                        .copied()
                        .and_then(|si| self.symbols.get_mut(si.0))
                    {
                        sym.is_weak = true;
                    }
                }
            }
            // LIBMOD (0xA1): library module name — we ignore it, but recognise it
            // to avoid spurious debug noise in future logging.
            0xA1 => {}
            // All other COMENT classes are silently ignored.
            _ => {}
        }

        Ok(())
    }

    fn parse_alias(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse alias name (the alternate name being defined)
            let Some((alias_name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse substitute name (the existing symbol this aliases)
            let Some((_substitute_name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            let sym_idx = self.symbols.len();
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name: alias_name,
                class: OmfSymbolClass::Alias,
                group_index: 0,
                segment_index: 0,
                frame_number: 0,
                offset: 0,
                communal_size: 0,
                type_index: 0,
                kind: read::SymbolKind::Unknown,
                is_weak: false,
                communal_data_type: 0,
            });
        }

        Ok(())
    }

    /// Resolve a communal segment reference from LEDATA/LIDATA.
    ///
    /// Borland C++ encodes COMDEF initialisation data as LEDATA/LIDATA records
    /// whose segment index field is set to (external_name_index + 0x4000).
    /// This avoids creating a SEGDEF for each communal variable.  We lazily
    /// create a synthetic segment on first reference and point the communal
    /// symbol at it.
    fn resolve_communal_segment(&mut self, ext_idx: u16) -> Result<usize> {
        let ext_0 = (ext_idx - 1) as usize;
        if ext_0 >= self.external_order.len() {
            return Err(Error("Communal segment index out of range"));
        }
        let sym_idx = self.external_order[ext_0].0;

        // If we already created a segment for this communal, reuse it.
        if self.symbols[sym_idx].segment_index > 0 {
            return Ok((self.symbols[sym_idx].segment_index - 1) as usize);
        }

        // All communal segments share the name "VIRDEF" so that
        // merge_same_name_segments() groups them by class (CODE vs DATA)
        // into one or two sections, rather than creating a separate section
        // per communal symbol.
        let name_index = self.get_or_add_name(b"VIRDEF");

        // For VIRDEFs (communal_data_type 1..0x5F), the data_type is a 1-based
        // segment index.  Copy the class from that SEGDEF so the synthetic
        // segment inherits the correct SectionKind (Text for CODE, Data for DATA).
        let virdef_seg = self.symbols[sym_idx].communal_data_type;
        let class_index = if (1..=0x5F).contains(&virdef_seg) {
            let seg_0 = (virdef_seg as usize).wrapping_sub(1);
            self.segments
                .get(seg_0)
                .map(|s| s.class_index)
                .unwrap_or(0)
        } else {
            0
        };

        // Create a synthetic segment for this communal variable.
        let seg_idx = self.segments.len();
        self.segments.push(OmfSegment {
            name_index,
            class_index,
            overlay_index: 0,
            alignment: omf::SegmentAlignment::DWord,
            combination: omf::SegmentCombination::Common,
            use32: true,
            length: self.symbols[sym_idx].communal_size,
            data_chunks: Vec::new(),
            relocations: Vec::new(),
            is_comdat: false,
            is_communal: true,
            line_numbers: Vec::new(),
        });

        // Point the communal symbol at its segment (1-based).
        self.symbols[sym_idx].segment_index = (seg_idx + 1) as u16;

        Ok(seg_idx)
    }

    fn parse_ledata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Parse segment index
        let (segment_index, size) =
            read_index(data).ok_or(Error("Invalid segment index in LEDATA"))?;
        offset += size;

        // Communal reference: Borland encodes COMDEF segment index as
        // (external_name_index + 0x4000).
        let seg_idx_0based = if segment_index > 0x4000 {
            self.resolve_communal_segment(segment_index - 0x4000)?
        } else {
            if segment_index == 0 || segment_index > self.segments.len() as u16 {
                return Err(Error("Invalid segment index in LEDATA"));
            }
            (segment_index - 1) as usize
        };

        // Parse data offset
        let data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated LEDATA record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated LEDATA record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // Store reference to data chunk
        let segment = &mut self.segments[seg_idx_0based];

        // Store the data chunk reference and extend segment.length if needed.
        // Watcom's "one segment per COMDAT" model emits SEGDEF with length=0
        // and provides actual bytes via a subsequent LEDATA record.  We must
        // update the segment length so that section.size() reflects reality.
        if offset < data.len() {
            let chunk_len = (data.len() - offset) as u32;
            let new_end = data_offset.saturating_add(chunk_len);
            if new_end > segment.length {
                segment.length = new_end;
            }
            segment
                .data_chunks
                .push((data_offset, OmfDataChunk::Direct(&data[offset..])));
        }

        Ok((seg_idx_0based, data_offset))
    }

    fn parse_fixupp(
        &mut self,
        data: &'data [u8],
        is_32bit: bool,
        seg_idx: usize,
        data_offset: u32,
        frame_threads: &mut [Option<ThreadDef>; 4],
        target_threads: &mut [Option<ThreadDef>; 4],
    ) -> Result<()> {
        let reloc_start = self.segments[seg_idx].relocations.len();
        parse_fixupp_records(
            data,
            is_32bit,
            data_offset,
            frame_threads,
            target_threads,
            &mut self.segments[seg_idx].relocations,
        )?;
        // Borland C++ encodes communal segment references in FIXUPP targets
        // using the same scheme as LEDATA: segment_index = ext_index + 0x4000.
        // Resolve these to actual (synthetic) segment indices.
        self.resolve_fixupp_communal_refs(seg_idx, reloc_start)
    }

    /// Post-process fixups to resolve Borland communal segment references.
    ///
    /// Borland C++ stores virtual-table and RTTI initialisers in COMDEF
    /// communal variables.  FIXUPP records targeting these variables encode
    /// the segment index as `ext_name_index + 0x4000`, the same scheme used
    /// in LEDATA/LIDATA/PUBDEF.  This method resolves such references in
    /// both the target and frame fields of each fixup, creating synthetic
    /// segments via `resolve_communal_segment()` as needed.
    fn resolve_fixupp_communal_refs(
        &mut self,
        seg_idx: usize,
        reloc_start: usize,
    ) -> Result<()> {
        // Collect indices that need resolving to avoid borrow conflicts
        // (resolve_communal_segment mutates self.segments/self.symbols/self.names).
        let mut target_fixups: Vec<(usize, u16)> = Vec::new();
        let mut frame_fixups: Vec<(usize, u16)> = Vec::new();

        for (i, fixup) in self.segments[seg_idx].relocations[reloc_start..]
            .iter()
            .enumerate()
        {
            if matches!(fixup.target_method, TargetMethod::SegmentIndex)
                && fixup.target_index > 0x4000
            {
                target_fixups.push((reloc_start + i, fixup.target_index - 0x4000));
            }
            if matches!(fixup.frame_method, FrameMethod::SegmentIndex)
                && fixup.frame_index > 0x4000
            {
                frame_fixups.push((reloc_start + i, fixup.frame_index - 0x4000));
            }
        }

        for (fixup_idx, ext_idx) in target_fixups {
            let seg_0 = self.resolve_communal_segment(ext_idx)?;
            self.segments[seg_idx].relocations[fixup_idx].target_index = (seg_0 + 1) as u16;
        }
        for (fixup_idx, ext_idx) in frame_fixups {
            let seg_0 = self.resolve_communal_segment(ext_idx)?;
            self.segments[seg_idx].relocations[fixup_idx].frame_index = (seg_0 + 1) as u16;
        }

        Ok(())
    }

    /// Same as `resolve_fixupp_communal_refs` but for COMDAT relocations.
    fn resolve_comdat_fixupp_communal_refs(
        &mut self,
        comdat_idx: usize,
        reloc_start: usize,
    ) -> Result<()> {
        let mut target_fixups: Vec<(usize, u16)> = Vec::new();
        let mut frame_fixups: Vec<(usize, u16)> = Vec::new();

        for (i, fixup) in self.comdats[comdat_idx].relocations[reloc_start..]
            .iter()
            .enumerate()
        {
            if matches!(fixup.target_method, TargetMethod::SegmentIndex)
                && fixup.target_index > 0x4000
            {
                target_fixups.push((reloc_start + i, fixup.target_index - 0x4000));
            }
            if matches!(fixup.frame_method, FrameMethod::SegmentIndex)
                && fixup.frame_index > 0x4000
            {
                frame_fixups.push((reloc_start + i, fixup.frame_index - 0x4000));
            }
        }

        for (fixup_idx, ext_idx) in target_fixups {
            let seg_0 = self.resolve_communal_segment(ext_idx)?;
            self.comdats[comdat_idx].relocations[fixup_idx].target_index = (seg_0 + 1) as u16;
        }
        for (fixup_idx, ext_idx) in frame_fixups {
            let seg_0 = self.resolve_communal_segment(ext_idx)?;
            self.comdats[comdat_idx].relocations[fixup_idx].frame_index = (seg_0 + 1) as u16;
        }

        Ok(())
    }

    fn parse_lidata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Read segment index
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index in LIDATA"))?;
        offset += size;

        // Communal reference: same encoding as LEDATA.
        let seg_idx_0based = if segment_index > 0x4000 {
            self.resolve_communal_segment(segment_index - 0x4000)?
        } else {
            if segment_index == 0 || segment_index > self.segments.len() as u16 {
                return Err(Error("Invalid segment index in LIDATA"));
            }
            (segment_index - 1) as usize
        };

        // Read data offset
        let data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated LIDATA record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated LIDATA record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // For LIDATA, we need to store the unexpanded data and expand on demand
        if offset < data.len() {
            self.segments[seg_idx_0based]
                .data_chunks
                .push((data_offset, OmfDataChunk::Iterated(&data[offset..])));
        }

        Ok((seg_idx_0based, data_offset))
    }

    /// Get the module name
    pub fn module_name(&self) -> Option<&'data str> {
        self.module_name
    }

    /// Get the segments as a slice
    pub fn raw_segments(&self) -> &[OmfSegment<'data>] {
        &self.segments
    }

    /// Get symbol by external-name index (1-based, as used in FIXUPP records)
    pub fn external_symbol(&self, external_index: u16) -> Option<&OmfSymbol<'data>> {
        let symbol_index = self
            .external_order
            .get(external_index.checked_sub(1)? as usize)?;
        self.symbols.get(symbol_index.0)
    }

    /// Get a name by index (1-based)
    pub fn get_name(&self, index: u16) -> Option<&'data [u8]> {
        let name_index = index.checked_sub(1)?;
        self.names.get(name_index as usize).copied()
    }

    /// Find or create a name in the LNAMES table, returning its 1-based index.
    fn get_or_add_name(&mut self, name: &'data [u8]) -> u16 {
        // Check if the name already exists.
        for (i, existing) in self.names.iter().enumerate() {
            if *existing == name {
                return (i + 1) as u16;
            }
        }
        // Add a new entry.
        let idx = (self.names.len() + 1) as u16;
        self.names.push(name);
        idx
    }

    /// Get all symbols (for iteration)
    pub fn raw_symbols(&self) -> &[OmfSymbol<'data>] {
        &self.symbols
    }

    /// Get line number entries for a segment (0-based index).
    ///
    /// Returns `(line_number, segment_offset)` pairs parsed from LINNUM records.
    pub fn segment_line_numbers(&self, segment_index: usize) -> &[(u16, u32)] {
        self.segments
            .get(segment_index)
            .map(|s| s.line_numbers.as_slice())
            .unwrap_or(&[])
    }
}

impl<'data, R: ReadRef<'data>> Object<'data> for OmfFile<'data, R> {
    type Segment<'file>
        = OmfSegmentRef<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SegmentIterator<'file>
        = OmfSegmentIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Section<'file>
        = OmfSection<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SectionIterator<'file>
        = OmfSectionIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Comdat<'file>
        = OmfComdat<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ComdatIterator<'file>
        = OmfComdatIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Symbol<'file>
        = OmfSymbol<'data>
    where
        Self: 'file,
        'data: 'file;
    type SymbolIterator<'file>
        = OmfSymbolIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SymbolTable<'file>
        = OmfSymbolTable<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type DynamicRelocationIterator<'file>
        = NoDynamicRelocationIterator
    where
        Self: 'file,
        'data: 'file;

    fn architecture(&self) -> Architecture {
        // All OMF files are x86. I8086 is not a variant in this crate, so we
        // always return I386 — the per-section `SectionFlags::Omf { use32 }`
        // already exposes the 16-bit vs 32-bit distinction to consumers.
        Architecture::I386
    }

    fn sub_architecture(&self) -> Option<SubArchitecture> {
        None
    }

    fn is_little_endian(&self) -> bool {
        true
    }

    fn is_64(&self) -> bool {
        false
    }

    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    fn segments(&self) -> Self::SegmentIterator<'_> {
        OmfSegmentIterator {
            file: self,
            index: 0,
        }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<Self::Section<'file>> {
        self.sections()
            .find(|section| section.name_bytes() == Ok(section_name))
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<Self::Section<'_>> {
        let idx = index
            .0
            .checked_sub(1)
            .ok_or(Error("Invalid section index"))?;
        if idx < self.segments.len() {
            Ok(OmfSection {
                file: self,
                index: idx,
            })
        } else {
            Err(Error("Section index out of bounds"))
        }
    }

    fn sections(&self) -> Self::SectionIterator<'_> {
        OmfSectionIterator {
            file: self,
            index: 0,
        }
    }

    fn comdats(&self) -> Self::ComdatIterator<'_> {
        OmfComdatIterator {
            file: self,
            index: 0,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol<'_>> {
        let idx = index.0;
        if idx >= self.symbols.len() {
            return Err(Error("Symbol index out of bounds"));
        }
        Ok(self.symbols[idx].clone())
    }

    fn symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            file: self,
            index: 0,
        }
    }

    fn symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        Some(OmfSymbolTable { file: self })
    }

    fn dynamic_symbols(&self) -> Self::SymbolIterator<'_> {
        // Start at symbols.len() so get() always returns None — a safe empty iterator.
        OmfSymbolIterator {
            file: self,
            index: self.symbols.len(),
        }
    }

    fn dynamic_symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        None
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn imports(&self) -> Result<Vec<Import<'data>>> {
        Ok(self
            .raw_symbols()
            .iter()
            .filter(|sym| {
                matches!(
                    sym.class,
                    OmfSymbolClass::External | OmfSymbolClass::ComdatExternal
                )
            })
            .map(|ext| Import {
                library: ByteString(b""),
                name: ByteString(ext.name),
            })
            .collect())
    }

    fn exports(&self) -> Result<Vec<Export<'data>>> {
        Ok(self
            .raw_symbols()
            .iter()
            .filter(|sym| sym.class == OmfSymbolClass::Public)
            .map(|pub_sym| Export {
                name: ByteString(pub_sym.name),
                address: pub_sym.offset as u64,
            })
            .collect())
    }

    fn has_debug_symbols(&self) -> bool {
        false
    }

    fn mach_uuid(&self) -> Result<Option<[u8; 16]>> {
        Ok(None)
    }

    fn build_id(&self) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn gnu_debuglink(&self) -> Result<Option<(&'data [u8], u32)>> {
        Ok(None)
    }

    fn gnu_debugaltlink(&self) -> Result<Option<(&'data [u8], &'data [u8])>> {
        Ok(None)
    }

    fn pdb_info(&self) -> Result<Option<CodeView<'_>>> {
        Ok(None)
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    fn entry(&self) -> u64 {
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}

/// Thread definition for FIXUPP parsing
#[derive(Debug, Clone, Copy)]
struct ThreadDef {
    /// 3-bit method (frame or target method)
    method: u8,
    /// Index value (meaning depends on method)
    index: u16,
}

/// Target method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(super) enum TargetMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
}

/// Frame method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(super) enum FrameMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
    /// Location (use fixup location)
    Location = 4,
    /// Target (use target's frame)
    Target = 5,
}

/// Parse FIXUPP subrecords (THREAD and FIXUP) from a FIXUPP record body.
///
/// This is a standalone function (not a method) to avoid borrow-checker
/// conflicts: the caller can pass `&mut segment.relocations` or
/// `&mut comdat.relocations` without a double-mutable-borrow on `self`.
fn parse_fixupp_records(
    data: &[u8],
    is_32bit: bool,
    data_offset: u32,
    frame_threads: &mut [Option<ThreadDef>; 4],
    target_threads: &mut [Option<ThreadDef>; 4],
    relocations: &mut Vec<OmfFixup>,
) -> Result<()> {
    let mut offset = 0;

    while offset < data.len() {
        let b = data[offset];
        offset += 1;

        if (b & 0x80) == 0 {
            // THREAD subrecord
            let is_frame = (b & 0x40) != 0; // D-bit
            let method = (b >> 2) & 0x07; // Method bits
            let thread_num = (b & 0x03) as usize; // Thread number (0-3)

            let index = if method < 3 {
                // Methods 0-2 have an index
                let (idx, size) = read_index(&data[offset..])
                    .ok_or(Error("Invalid index in THREAD subrecord"))?;
                offset += size;
                idx
            } else if method == 3 {
                // Method 3 has a raw frame number
                if offset + 2 > data.len() {
                    return Err(Error("Invalid frame number in THREAD subrecord"));
                }
                let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                frame_num
            } else {
                0
            };

            // Store the thread definition
            let thread_def = ThreadDef { method, index };
            if is_frame {
                frame_threads[thread_num] = Some(thread_def);
            } else {
                target_threads[thread_num] = Some(thread_def);
            }
        } else {
            // FIXUP subrecord
            if offset + 1 > data.len() {
                return Err(Error("Truncated FIXUP location"));
            }
            let locat = data[offset] as u32 | (((b as u32) & 0x03) << 8);
            offset += 1;

            let location = match (b >> 2) & 0x0F {
                0 => omf::FixupLocation::LowByte,
                1 => omf::FixupLocation::Offset,
                2 => omf::FixupLocation::Base,
                3 => omf::FixupLocation::Pointer,
                4 => omf::FixupLocation::HighByte,
                5 => omf::FixupLocation::LoaderOffset,
                9 => omf::FixupLocation::Offset32,
                11 => omf::FixupLocation::Pointer48,
                13 => omf::FixupLocation::LoaderOffset32,
                _ => continue, // Skip unknown fixup types
            };

            // Parse fix data byte
            if offset >= data.len() {
                return Err(Error("Truncated FIXUP fix data"));
            }
            let fix_data = data[offset];
            offset += 1;

            // Check F-bit (bit 7 of fix_data)
            let frame_via_thread = (fix_data & 0x80) != 0;
            let (frame_method, frame_index) = if frame_via_thread {
                // F=1: Use frame thread
                let thread_num = ((fix_data >> 4) & 0x03) as usize;
                match frame_threads[thread_num] {
                    Some(thread) => {
                        let method = match thread.method {
                            0 => FrameMethod::SegmentIndex,
                            1 => FrameMethod::GroupIndex,
                            2 => FrameMethod::ExternalIndex,
                            3 => FrameMethod::FrameNumber,
                            4 => FrameMethod::Location,
                            5 => FrameMethod::Target,
                            _ => return Err(Error("Invalid frame method in thread")),
                        };
                        (method, thread.index)
                    }
                    None => return Err(Error("Undefined frame thread in FIXUP")),
                }
            } else {
                // F=0: Read frame datum
                let method_bits = (fix_data >> 4) & 0x07;
                let method = match method_bits {
                    0 => FrameMethod::SegmentIndex,
                    1 => FrameMethod::GroupIndex,
                    2 => FrameMethod::ExternalIndex,
                    3 => FrameMethod::FrameNumber,
                    4 => FrameMethod::Location,
                    5 => FrameMethod::Target,
                    _ => return Err(Error("Invalid frame method in FIXUP")),
                };
                let index = match method {
                    FrameMethod::SegmentIndex
                    | FrameMethod::GroupIndex
                    | FrameMethod::ExternalIndex => {
                        let (idx, size) = read_index(&data[offset..])
                            .ok_or(Error("Truncated FIXUP frame datum: missing index data"))?;
                        offset += size;
                        idx
                    }
                    FrameMethod::FrameNumber => {
                        if offset + 2 > data.len() {
                            return Err(Error(
                                "Truncated FIXUP frame datum: missing frame number",
                            ));
                        }
                        let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                        offset += 2;
                        frame_num
                    }
                    FrameMethod::Location | FrameMethod::Target => 0,
                };
                (method, index)
            };

            // Check T-bit (bit 3 of fix_data)
            let target_via_thread = (fix_data & 0x08) != 0;
            let (target_method, target_index) = if target_via_thread {
                // T=1: Use target thread
                let thread_num = (fix_data & 0x03) as usize;
                match target_threads[thread_num] {
                    Some(thread) => {
                        // Only check the low 2 bits of method for target
                        let method = match thread.method & 0x03 {
                            0 => TargetMethod::SegmentIndex,
                            1 => TargetMethod::GroupIndex,
                            2 => TargetMethod::ExternalIndex,
                            3 => TargetMethod::FrameNumber,
                            _ => return Err(Error("Invalid target method in thread")),
                        };
                        (method, thread.index)
                    }
                    None => return Err(Error("Undefined target thread in FIXUP")),
                }
            } else {
                // T=0: Read target datum
                // Only check the low 2 bits of method for target
                let method = match fix_data & 0x03 {
                    0 => TargetMethod::SegmentIndex,
                    1 => TargetMethod::GroupIndex,
                    2 => TargetMethod::ExternalIndex,
                    3 => TargetMethod::FrameNumber,
                    _ => return Err(Error("Invalid frame method in FIXUP")),
                };
                let index = match method {
                    TargetMethod::SegmentIndex
                    | TargetMethod::GroupIndex
                    | TargetMethod::ExternalIndex => {
                        let (idx, size) = read_index(&data[offset..])
                            .ok_or(Error("Truncated FIXUP target datum: missing index data"))?;
                        offset += size;
                        idx
                    }
                    TargetMethod::FrameNumber => {
                        if offset + 2 > data.len() {
                            return Err(Error(
                                "Truncated FIXUP target datum: missing frame number",
                            ));
                        }
                        let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                        offset += 2;
                        frame_num
                    }
                };
                (method, index)
            };

            // Parse target displacement if present (P=0)
            let has_displacement = (fix_data & 0x04) == 0;
            let target_displacement = if has_displacement {
                if is_32bit {
                    if offset + 4 <= data.len() {
                        let disp = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]);
                        offset += 4;
                        disp
                    } else {
                        return Err(Error("Truncated FIXUP 32-bit displacement"));
                    }
                } else if offset + 2 <= data.len() {
                    let disp = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                    offset += 2;
                    disp
                } else {
                    return Err(Error("Truncated FIXUP 16-bit displacement"));
                }
            } else {
                0
            };

            // Extract M-bit (bit 6 of the first locat byte `b`).
            // M=1 → segment-relative, M=0 → self-relative (PC-relative).
            let is_segment_relative = (b & 0x40) != 0;
            relocations.push(OmfFixup {
                offset: data_offset + locat,
                location,
                frame_method,
                target_method,
                frame_index,
                target_index,
                target_displacement,
                is_segment_relative,
            });
        }
    }

    Ok(())
}

/// Expand a LIDATA block into a newly allocated buffer
pub(super) fn expand_lidata_block(data: &[u8]) -> Result<Vec<u8>> {
    let (orig_size, expanded_size) = lidata_block_expanded_size(data)?;
    let mut result = vec![0u8; expanded_size];
    let mut write_offset = 0usize;
    let consumed = expand_lidata_block_into(data, &mut result, &mut write_offset)?;

    debug_assert_eq!(write_offset, expanded_size);
    debug_assert_eq!(consumed, orig_size);

    Ok(result)
}

fn expand_lidata_block_into(
    data: &[u8],
    output: &mut [u8],
    write_offset: &mut usize,
) -> Result<usize> {
    let mut offset = 0;

    let (repeat_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    if repeat_count == 0 {
        return lidata_block_size(data);
    }

    let repeat_count = repeat_count as usize;

    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        if offset >= data.len() {
            return Ok(offset);
        }

        let data_length = data[offset] as usize;
        offset += 1;

        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }

        let block_data = &data[offset..offset + data_length];
        offset += data_length;

        for _ in 0..repeat_count {
            let end = write_offset
                .checked_add(data_length)
                .ok_or(Error("LIDATA expanded size overflow"))?;
            if end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            output[*write_offset..end].copy_from_slice(block_data);
            *write_offset = end;
        }
    } else {
        let mut block_offset = offset;
        let iteration_start = *write_offset;

        for _ in 0..block_count {
            let block_size = lidata_block_size(&data[block_offset..])?;
            let block_consumed =
                expand_lidata_block_into(&data[block_offset..], output, write_offset)?;

            debug_assert_eq!(block_size, block_consumed);
            block_offset = block_offset
                .checked_add(block_size)
                .ok_or(Error("LIDATA block size overflow"))?;
            if block_offset > data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
        }

        let iteration_len = *write_offset - iteration_start;

        for _ in 1..repeat_count {
            let dest_start = *write_offset;
            let dest_end = dest_start
                .checked_add(iteration_len)
                .ok_or(Error("LIDATA expanded size overflow"))?;
            if dest_end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            if iteration_len != 0 {
                output.copy_within(iteration_start..iteration_start + iteration_len, dest_start);
            }
            *write_offset = dest_end;
        }

        offset = block_offset;
    }

    Ok(offset)
}

fn lidata_block_expanded_size(data: &[u8]) -> Result<(usize, usize)> {
    let mut offset = 0;

    let (repeat_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    if repeat_count == 0 {
        let consumed = lidata_block_size(data)?;
        if consumed > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        return Ok((consumed, 0));
    }

    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        if offset >= data.len() {
            return Ok((offset, 0));
        }

        let data_length = data[offset] as usize;
        offset += 1;

        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }

        offset += data_length;

        let expanded = data_length
            .checked_mul(repeat_count as usize)
            .ok_or(Error("LIDATA expanded size overflow"))?;
        Ok((offset, expanded))
    } else {
        let mut block_offset = offset;
        let mut single_iteration = 0usize;

        for _ in 0..block_count {
            let (consumed, expanded) = lidata_block_expanded_size(&data[block_offset..])?;
            block_offset = block_offset
                .checked_add(consumed)
                .ok_or(Error("LIDATA block size overflow"))?;
            if block_offset > data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
            single_iteration = single_iteration
                .checked_add(expanded)
                .ok_or(Error("LIDATA expanded size overflow"))?;
        }

        let expanded = single_iteration
            .checked_mul(repeat_count as usize)
            .ok_or(Error("LIDATA expanded size overflow"))?;

        Ok((block_offset, expanded))
    }
}

/// Helper function to calculate LIDATA block size
fn lidata_block_size(data: &[u8]) -> Result<usize> {
    let mut offset = 0;

    // Read repeat count
    let (_, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    // Read block count
    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        // Leaf block
        if offset >= data.len() {
            return Ok(offset);
        }
        let data_length = data[offset] as usize;
        offset += 1 + data_length;
    } else {
        // Nested blocks
        for _ in 0..block_count {
            offset += lidata_block_size(&data[offset..])?;
        }
    }

    Ok(offset)
}

/// Helper to read an OMF index (1 or 2 bytes)
fn read_index(data: &[u8]) -> Option<(u16, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte & 0x80 == 0 {
        // 1-byte index
        Some((first_byte as u16, 1))
    } else if data.len() >= 2 {
        // 2-byte index
        let high = (first_byte & 0x7F) as u16;
        let low = data[1] as u16;
        Some((high << 8 | low, 2))
    } else {
        None
    }
}

/// Helper to read a counted string (length byte followed by string)
fn read_counted_string(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }

    let length = data[0] as usize;
    // Need at least 1 (length byte) + length (string bytes) total.
    if data.len() > length {
        Some((&data[1..1 + length], 1 + length))
    } else {
        None
    }
}

/// Read an encoded value (used in LIDATA for repeat counts and block counts)
/// Returns the value and number of bytes consumed
fn read_encoded_value(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte < 0x80 {
        // Single byte value (0-127)
        Some((first_byte as u32, 1))
    } else if first_byte == 0x81 {
        // Two byte value: 0x81 followed by 16-bit little-endian value
        if data.len() >= 3 {
            let value = u16::from_le_bytes([data[1], data[2]]) as u32;
            Some((value, 3))
        } else {
            None
        }
    } else if first_byte == 0x84 {
        // Three byte value: 0x84 followed by 24-bit little-endian value
        if data.len() >= 4 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], 0]);
            Some((value, 4))
        } else {
            None
        }
    } else if first_byte == 0x88 {
        // Four byte value: 0x88 followed by 32-bit little-endian value
        if data.len() >= 5 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Some((value, 5))
        } else {
            None
        }
    } else {
        // Unknown encoding
        None
    }
}

/// Create an empty placeholder segment used during `merge_same_name_segments()`
/// to take ownership of segments via `core::mem::replace()`.
fn dummy_segment<'data>() -> OmfSegment<'data> {
    OmfSegment {
        name_index: 0,
        class_index: 0,
        overlay_index: 0,
        alignment: omf::SegmentAlignment::Byte,
        combination: omf::SegmentCombination::Private,
        use32: false,
        length: 0,
        data_chunks: Vec::new(),
        relocations: Vec::new(),
        is_comdat: false,
        is_communal: false,
        line_numbers: Vec::new(),
    }
}

/// Trim trailing x86 NOP-equivalent alignment padding from a code slice.
///
/// Returns the length of the slice with trailing NOP patterns removed.
/// Recognised patterns (all commonly used by Borland C++ and other x86
/// compilers for inter-function alignment):
///
///  - `90`                      → `nop`
///  - `8B C0`                   → `mov eax, eax`
///  - `8D 40 00`                → `lea eax, [eax]`
///  - `8D 49 00`                → `lea ecx, [ecx]`
///  - `05 00 00 00 00`          → `add eax, 0`
///  - `8D 80 00 00 00 00`       → `lea eax, [eax+0x00000000]`
///  - `0F 1F 00`                → multi-byte NOP (3)
///  - `0F 1F 40 00`             → multi-byte NOP (4)
///  - `0F 1F 44 00 00`          → multi-byte NOP (5)
///  - `66 0F 1F 44 00 00`       → multi-byte NOP (6)
///  - `0F 1F 80 00 00 00 00`    → multi-byte NOP (7)
///  - `0F 1F 84 00 00 00 00 00` → multi-byte NOP (8)
///  - `CC`                      → `int3` (debug break / padding)
fn trim_trailing_x86_nops(data: &[u8]) -> usize {
    let mut pos = data.len();

    loop {
        if pos == 0 {
            break;
        }

        // Try patterns longest-first to consume as much as possible per step.
        if pos >= 8
            && data[pos - 8..pos] == [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
        {
            pos -= 8;
        } else if pos >= 7
            && data[pos - 7..pos] == [0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]
        {
            pos -= 7;
        } else if pos >= 6
            && data[pos - 6..pos] == [0x8D, 0x80, 0x00, 0x00, 0x00, 0x00]
        {
            pos -= 6; // lea eax, [eax+0x00000000]
        } else if pos >= 6
            && data[pos - 6..pos] == [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]
        {
            pos -= 6;
        } else if pos >= 5 && data[pos - 5..pos] == [0x05, 0x00, 0x00, 0x00, 0x00] {
            pos -= 5; // add eax, 0
        } else if pos >= 5 && data[pos - 5..pos] == [0x0F, 0x1F, 0x44, 0x00, 0x00] {
            pos -= 5;
        } else if pos >= 4 && data[pos - 4..pos] == [0x0F, 0x1F, 0x40, 0x00] {
            pos -= 4;
        } else if pos >= 3 && data[pos - 3..pos] == [0x8D, 0x40, 0x00] {
            pos -= 3; // lea eax, [eax]
        } else if pos >= 3 && data[pos - 3..pos] == [0x8D, 0x49, 0x00] {
            pos -= 3; // lea ecx, [ecx]
        } else if pos >= 3 && data[pos - 3..pos] == [0x0F, 0x1F, 0x00] {
            pos -= 3;
        } else if pos >= 2 && data[pos - 2..pos] == [0x8B, 0xC0] {
            pos -= 2; // mov eax, eax
        } else if pos >= 1 && data[pos - 1] == 0x90 {
            pos -= 1; // nop
        } else if pos >= 1 && data[pos - 1] == 0xCC {
            pos -= 1; // int3
        } else {
            break;
        }
    }

    pos
}
