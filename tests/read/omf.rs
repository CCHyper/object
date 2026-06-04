//! OMF read tests using in-memory fixture builder (no external assembler required).
//!
//! All tests build minimal but valid OMF binary payloads in memory and parse
//! them through the public `object` API, exercising each feature end-to-end.

#![cfg(all(feature = "read", feature = "omf"))]

use object::{
    Architecture, BinaryFormat, ComdatKind, Object, ObjectComdat, ObjectSection, ObjectSymbol,
    ObjectSymbolTable, RelocationKind, RelocationTarget, SymbolKind, SymbolScope, SymbolSection,
};

// ---------------------------------------------------------------------------
// Minimal OMF byte-level builder
// ---------------------------------------------------------------------------

/// Emit a variable-length OMF index (1- or 2-byte).
fn push_index(buf: &mut Vec<u8>, value: u16) {
    if value < 0x80 {
        buf.push(value as u8);
    } else {
        buf.push(((value >> 8) as u8) | 0x80);
        buf.push(value as u8);
    }
}

/// Emit a length-prefixed string (counted string).
fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s);
}

/// Emit a complete OMF record: type, length (little-endian u16), data, checksum=0.
fn push_record(out: &mut Vec<u8>, rec_type: u8, data: &[u8]) {
    out.push(rec_type);
    let len = (data.len() + 1) as u16; // +1 for the checksum byte
    out.push(len as u8);
    out.push((len >> 8) as u8);
    out.extend_from_slice(data);
    out.push(0); // checksum (0 = ignored by our parser)
}

/// Build THEADR record.
fn theadr(out: &mut Vec<u8>, name: &[u8]) {
    let mut d = Vec::new();
    push_string(&mut d, name);
    push_record(out, 0x80, &d);
}

/// Build LNAMES record for one or more names.
fn lnames(out: &mut Vec<u8>, names: &[&[u8]]) {
    let mut d = Vec::new();
    for n in names {
        push_string(&mut d, n);
    }
    push_record(out, 0x96, &d);
}

/// Build SEGDEF (16-bit).
///
/// acbp byte: bits 7-5 = alignment (4 = DWord), bits 4-2 = combination, bit 0 = use32.
/// `seg_name_idx` and `class_name_idx` are 1-based indices into the LNAMES table.
fn segdef(out: &mut Vec<u8>, acbp: u8, length: u16, seg_name_idx: u8, class_name_idx: u8) {
    let mut d = Vec::new();
    d.push(acbp);
    // length
    d.push(length as u8);
    d.push((length >> 8) as u8);
    // seg name index, class name index, overlay name index
    push_index(&mut d, seg_name_idx as u16);
    push_index(&mut d, class_name_idx as u16);
    push_index(&mut d, 0); // overlay = none
    push_record(out, 0x98, &d);
}

/// Build SEGDEF32 (32-bit).
fn segdef32(out: &mut Vec<u8>, acbp: u8, length: u32, seg_name_idx: u8, class_name_idx: u8) {
    let mut d = Vec::new();
    d.push(acbp);
    d.push(length as u8);
    d.push((length >> 8) as u8);
    d.push((length >> 16) as u8);
    d.push((length >> 24) as u8);
    push_index(&mut d, seg_name_idx as u16);
    push_index(&mut d, class_name_idx as u16);
    push_index(&mut d, 0);
    push_record(out, 0x99, &d);
}

/// Build PUBDEF (16-bit). `group_idx`=0 means none. `seg_idx`=1-based.
fn pubdef(out: &mut Vec<u8>, group_idx: u16, seg_idx: u16, symbols: &[(&[u8], u16)]) {
    let mut d = Vec::new();
    push_index(&mut d, group_idx);
    push_index(&mut d, seg_idx);
    if seg_idx == 0 {
        // absolute: emit frame number
        d.push(0);
        d.push(0);
    }
    for (name, offset) in symbols {
        push_string(&mut d, name);
        d.push(*offset as u8);
        d.push((*offset >> 8) as u8);
        push_index(&mut d, 0); // type index
    }
    push_record(out, 0x90, &d);
}

/// Build PUBDEF32 (32-bit offsets).
fn pubdef32(out: &mut Vec<u8>, group_idx: u16, seg_idx: u16, symbols: &[(&[u8], u32)]) {
    let mut d = Vec::new();
    push_index(&mut d, group_idx);
    push_index(&mut d, seg_idx);
    for (name, offset) in symbols {
        push_string(&mut d, name);
        d.push(*offset as u8);
        d.push((*offset >> 8) as u8);
        d.push((*offset >> 16) as u8);
        d.push((*offset >> 24) as u8);
        push_index(&mut d, 0);
    }
    push_record(out, 0x91, &d);
}

/// Build EXTDEF record.
fn extdef(out: &mut Vec<u8>, names: &[&[u8]]) {
    let mut d = Vec::new();
    for name in names {
        push_string(&mut d, name);
        push_index(&mut d, 0); // type index
    }
    push_record(out, 0x8C, &d);
}

/// Build COMDEF record (communal variables).
fn comdef(out: &mut Vec<u8>, symbols: &[(&[u8], u32)]) {
    let mut d = Vec::new();
    for (name, size) in symbols {
        push_string(&mut d, name);
        push_index(&mut d, 0); // type index
        d.push(0x62); // NEAR data type
        // Encode the communal size as a variable-length value.
        // For sizes ≤ 128, use single byte (actually it starts at 129 for multibyte).
        // Per OMF spec: if size < 0x80, emit as single byte; otherwise use extended form.
        // We keep it simple: just emit as u16 for values ≤ 0x7F, else as 3-byte extended.
        if *size < 0x80 {
            d.push(*size as u8);
        } else if *size <= 0xFFFF {
            d.push(0x81); // 2-byte follows
            d.push(*size as u8);
            d.push((*size >> 8) as u8);
        } else {
            d.push(0x84); // 4-byte follows
            d.push(*size as u8);
            d.push((*size >> 8) as u8);
            d.push((*size >> 16) as u8);
            d.push((*size >> 24) as u8);
        }
    }
    push_record(out, 0xB0, &d);
}

/// Build LEDATA (16-bit): segment data.
fn ledata(out: &mut Vec<u8>, seg_idx: u16, data_offset: u16, data: &[u8]) {
    let mut d = Vec::new();
    push_index(&mut d, seg_idx);
    d.push(data_offset as u8);
    d.push((data_offset >> 8) as u8);
    d.extend_from_slice(data);
    push_record(out, 0xA0, &d);
}

/// Build FIXUPP (16-bit): a single self-relative 16-bit fixup.
fn fixupp_rel16(out: &mut Vec<u8>, fixup_offset: u8, target_ext_idx: u16) {
    let mut d = Vec::new();
    // FIXUP subrecord byte 1 (b):
    //   bit 7 = 1 (fixup marker)
    //   bit 6 = 0 (M-bit: self-relative)
    //   bits 5-2 = 0001 (location = 16-bit offset)
    //   bits 1-0 = 00 (upper bits of fixup offset within LEDATA)
    // 0x84 = 1000_0100
    d.push(0x84u8);
    d.push(fixup_offset); // low 8 bits of fixup offset in current LEDATA block

    // FIXUP fix data byte:
    //   bit 7 (F-bit)  = 0     → explicit frame datum
    //   bits 6-4       = 010   → frame method = ExternalIndex (bit 6=0 → self-relative)
    //   bit 3 (T-bit)  = 0     → explicit target datum
    //   bit 2 (P-bit)  = 1     → no displacement (target_displacement = 0)
    //   bits 1-0       = 10    → target method = ExternalIndex
    // 0x26 = 0010_0110
    d.push(0x26u8);
    push_index(&mut d, target_ext_idx); // frame datum (same external)
    push_index(&mut d, target_ext_idx); // target datum
    push_record(out, 0x9C, &d);
}

/// Build COMENT WKEXT record (0xA7): one weak external pair.
fn coment_wkext(out: &mut Vec<u8>, weak_ext_idx: u16, default_ext_idx: u16) {
    let mut d = Vec::new();
    d.push(0x00); // comment type
    d.push(0xA7); // WKEXT comment class
    push_index(&mut d, weak_ext_idx);
    push_index(&mut d, default_ext_idx);
    push_record(out, 0x88, &d);
}

/// Build ALIAS record.
fn alias(out: &mut Vec<u8>, pairs: &[(&[u8], &[u8])]) {
    let mut d = Vec::new();
    for (alias_name, subst_name) in pairs {
        push_string(&mut d, alias_name);
        push_string(&mut d, subst_name);
    }
    push_record(out, 0xC6, &d);
}

/// Build a FIXUPP32 (0x9D) with a segment-relative fixup targeting a segment index.
/// location=Offset32, M-bit=1 (segment-relative), target_method=SegmentIndex.
fn fixupp32_seg_relative(out: &mut Vec<u8>, fixup_offset: u16, target_seg_idx: u16, displacement: u32) {
    let mut d = Vec::new();
    // FIXUP subrecord byte 1 (b):
    //   bit 7   = 1       (fixup marker)
    //   bit 6   = 1       (M-bit: segment-relative)
    //   bits 5-2 = 1001   (location = Offset32)
    //   bits 1-0 = high 2 bits of fixup_offset
    let high2 = ((fixup_offset >> 8) & 0x03) as u8;
    d.push(0xE4 | high2); // 1110_01xx
    d.push(fixup_offset as u8); // low 8 bits

    // FIXUP fix data byte:
    //   bit 7 (F-bit) = 1     → frame determined by thread or target
    //   bits 6-4      = 101   → frame method = Target
    //   bit 3 (T-bit) = 0     → explicit target datum
    //   bit 2 (P-bit) = 0     → displacement present
    //   bits 1-0      = 00    → target method = SegmentIndex
    d.push(0xD0); // 1101_0000
    push_index(&mut d, target_seg_idx); // target datum
    d.extend_from_slice(&displacement.to_le_bytes()); // target displacement
    push_record(out, 0x9D, &d);
}

/// Build MODEND (non-main module).
/// Build LINNUM (16-bit): line number entries for a segment.
fn linnum(out: &mut Vec<u8>, group_idx: u16, seg_idx: u16, entries: &[(u16, u16)]) {
    let mut d = Vec::new();
    push_index(&mut d, group_idx);
    push_index(&mut d, seg_idx);
    for &(line, offset) in entries {
        d.push(line as u8);
        d.push((line >> 8) as u8);
        d.push(offset as u8);
        d.push((offset >> 8) as u8);
    }
    push_record(out, 0x94, &d);
}

/// Build LINNUM32: line number entries for a 32-bit segment.
fn linnum32(out: &mut Vec<u8>, group_idx: u16, seg_idx: u16, entries: &[(u16, u32)]) {
    let mut d = Vec::new();
    push_index(&mut d, group_idx);
    push_index(&mut d, seg_idx);
    for &(line, offset) in entries {
        d.push(line as u8);
        d.push((line >> 8) as u8);
        d.push(offset as u8);
        d.push((offset >> 8) as u8);
        d.push((offset >> 16) as u8);
        d.push((offset >> 24) as u8);
    }
    push_record(out, 0x95, &d);
}

fn modend(out: &mut Vec<u8>) {
    push_record(out, 0x8A, &[0x00]);
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a minimal OMF object with one 16-bit CODE segment and one symbol.
fn build_minimal_16bit() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"test.c");
    // LNAMES: idx1=_TEXT, idx2=CODE, idx3=_DATA, idx4=DATA, idx5=BSS, idx6=BSS
    lnames(&mut out, &[b"_TEXT", b"CODE", b"_DATA", b"DATA", b"BSS", b"BSS"]);
    // SEGDEF idx1=_TEXT/CODE, use16, DWord alignment (acbp=0x60), length=8
    segdef(&mut out, 0x60, 8, 1, 2);
    // SEGDEF idx2=_DATA/DATA, use16, Word alignment (acbp=0x40), length=4
    segdef(&mut out, 0x40, 4, 3, 4);
    // PUBDEF: _foo at offset 0 in segment 1
    pubdef(&mut out, 0, 1, &[(b"_foo", 0)]);
    // LEDATA: 8 bytes of code in segment 1
    ledata(&mut out, 1, 0, &[0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
    modend(&mut out);
    out
}

/// Build a 32-bit OMF object.
fn build_minimal_32bit() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"test32.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // use32 bit set (bit 0 of acbp = 1), DWord alignment → acbp = 0x61
    segdef32(&mut out, 0x61, 16, 1, 2);
    pubdef32(&mut out, 0, 1, &[(b"_bar", 0)]);
    modend(&mut out);
    out
}

/// Build an OMF object with EXTDEF, PUBDEF, FIXUPP (relocation).
fn build_with_relocation() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"reloc.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 4, 1, 2); // 4-byte code segment
    // Declare external symbol _printf (external index 1)
    extdef(&mut out, &[b"_printf"]);
    // LEDATA: 4-byte call placeholder
    ledata(&mut out, 1, 0, &[0xE8, 0x00, 0x00, 0x00]); // CALL rel16
    // FIXUPP: fixup at offset 1 in LEDATA, self-relative to external 1 (_printf)
    fixupp_rel16(&mut out, 1, 1);
    modend(&mut out);
    out
}

/// Build an OMF object with COMDEF communal variables.
fn build_with_comdef() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"comm.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 2, 1, 2);
    // COMDEF: two communal variables
    comdef(&mut out, &[(b"shared_buf", 100), (b"shared_flag", 4)]);
    modend(&mut out);
    out
}

/// Build an OMF object with WKEXT (weak external).
fn build_with_wkext() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"weak.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 2, 1, 2);
    // Two externals: _weak_sym (ext idx 1) with default _default_sym (ext idx 2)
    extdef(&mut out, &[b"_weak_sym", b"_default_sym"]);
    // WKEXT: mark ext idx 1 as weak, defaulting to ext idx 2
    coment_wkext(&mut out, 1, 2);
    modend(&mut out);
    out
}

/// Build an OMF object with ALIAS record.
fn build_with_alias() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"alias.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 2, 1, 2);
    // ALIAS: _foo_alias → _foo
    alias(&mut out, &[(b"_foo_alias", b"_foo")]);
    modend(&mut out);
    out
}

/// Build an OMF object with LIDATA (iterated data) — a 4-byte fill repeated 5 times = 20 bytes.
fn build_with_lidata() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"lidata.c");
    lnames(&mut out, &[b"_DATA", b"DATA"]);
    // Segment: 20 bytes
    segdef(&mut out, 0x40, 20, 1, 2);
    // LIDATA record at offset 0.
    // The iterated data block format (per read_encoded_value):
    //   repeat_count: 1 byte if < 0x80
    //   block_count:  1 byte if < 0x80 (0 = raw content follows)
    //   content_length: 1 byte
    //   content bytes...
    let mut d = Vec::new();
    push_index(&mut d, 1); // segment index
    d.push(0x00); // data offset low
    d.push(0x00); // data offset high
    // Iterated block: repeat 5 times, 0 sub-blocks, 4 bytes of content 0xCC
    d.push(5);    // repeat_count = 5 (single byte, < 0x80)
    d.push(0);    // block_count = 0 (raw content mode)
    d.push(4);    // content_length = 4
    d.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);
    push_record(&mut out, 0xA2, &d); // LIDATA
    modend(&mut out);
    out
}

/// Build an OMF object with a 64KB segment (B-bit set, stored length = 0).
fn build_big_segment() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"big.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // acbp: DWord alignment (bits7-5=100=0x80) + combination=Public (bits4-2=010=0x08)
    //       + B-bit=1 (bit1=0x02) + use32=0 (bit0=0)
    // = 0x80 | 0x08 | 0x02 = 0x8A
    // Stored length = 0, meaning the segment is 65536 bytes (64KB).
    segdef(&mut out, 0x8A, 0, 1, 2);
    modend(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_format_detection() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    assert_eq!(file.format(), BinaryFormat::Omf);
}

#[test]
fn test_16bit_architecture() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    // 16-bit OMF files are still x86; I8086 is not a crate variant so I386 is
    // returned. Per-section use32 flags carry the 16-bit vs 32-bit distinction.
    assert_eq!(file.architecture(), Architecture::I386);
}

#[test]
fn test_32bit_architecture() {
    let data = build_minimal_32bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    assert_eq!(file.architecture(), Architecture::I386);
}

#[test]
fn test_segment_count() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 2, "expected 2 segments (_TEXT and _DATA)");
}

#[test]
fn test_segment_names() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let names: Vec<&str> = file
        .sections()
        .map(|s| s.name().unwrap_or(""))
        .collect();
    assert!(names.contains(&"_TEXT"), "missing _TEXT: {:?}", names);
    assert!(names.contains(&"_DATA"), "missing _DATA: {:?}", names);
}

#[test]
fn test_segment_size() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let text = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("no _TEXT section");
    assert_eq!(text.size(), 8);
}

#[test]
fn test_pubdef_symbol() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();
    let foo = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_foo")
        .expect("_foo symbol not found");
    assert_eq!(foo.kind(), SymbolKind::Text);
    assert_eq!(foo.scope(), SymbolScope::Linkage);
    assert!(!foo.is_undefined());
    assert!(!foo.is_weak());
    // Section index should be 1 (1-based, _TEXT is the first segment).
    assert!(matches!(foo.section(), SymbolSection::Section(idx) if idx.0 == 1));
    // _foo data is [0xC3, 0x90×7] — a `ret` followed by 7 NOP alignment bytes.
    // After trailing-NOP trimming, the size should be 1 (just the `ret`).
    assert_eq!(foo.size(), 1, "_foo size after NOP trimming should be 1");
}

#[test]
fn test_32bit_pubdef_symbol() {
    let data = build_minimal_32bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();
    let bar = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_bar")
        .expect("_bar symbol not found");
    assert_eq!(bar.kind(), SymbolKind::Text);
    assert_eq!(bar.address(), 0);
}

#[test]
fn test_extdef_symbol() {
    let data = build_with_relocation();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();
    let printf = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_printf")
        .expect("_printf not found");
    assert!(printf.is_undefined());
    assert_eq!(printf.scope(), SymbolScope::Unknown);
}

#[test]
fn test_relocation_present() {
    let data = build_with_relocation();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let total_relocs: usize = file
        .sections()
        .map(|s| s.relocations().count())
        .sum();
    assert!(total_relocs > 0, "expected at least one relocation");
}

#[test]
fn test_relocation_kind_and_target() {
    let data = build_with_relocation();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let text = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("no _TEXT");
    let relocs: Vec<_> = text.relocations().collect();
    assert_eq!(relocs.len(), 1);
    let (offset, reloc) = &relocs[0];
    assert_eq!(*offset, 1, "fixup at byte offset 1");
    assert_eq!(reloc.kind(), RelocationKind::Relative);
    assert_eq!(reloc.size(), 16);
}

/// Verify the M-bit is read from the first locat byte (not fix_data).
///
/// This test builds a segment-relative 16-bit offset fixup (M=1).  Before
/// the fix, the M-bit was read from fix_data bit 6, which is part of the
/// frame method field — causing segment-relative fixups to be misidentified
/// as self-relative when frame method bits 6-4 happened to have bit 6 = 0.
#[test]
fn test_segment_relative_fixup_m_bit() {
    // Build an OMF with a segment-relative fixup (M=1) targeting segment 1.
    let mut out = Vec::new();
    theadr(&mut out, b"m_bit.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 4, 1, 2); // 4-byte code segment, idx=1
    // LEDATA: 4 bytes of data with a 16-bit pointer to patch at offset 0
    ledata(&mut out, 1, 0, &[0x00, 0x00, 0x90, 0x90]);

    // Build a FIXUPP with M=1 (segment-relative), Location=Offset (16-bit)
    let mut d = Vec::new();
    // FIXUP subrecord byte 1 (b):
    //   bit 7 = 1 (fixup marker)
    //   bit 6 = 1 (M-bit: segment-relative)
    //   bits 5-2 = 0001 (location = Offset, 16-bit)
    //   bits 1-0 = 00 (upper bits of offset)
    // 0xC4 = 1100_0100
    d.push(0xC4u8);
    d.push(0x00u8); // low 8 bits of fixup offset = 0

    // fix_data byte:
    //   bit 7 (F) = 0 → explicit frame datum
    //   bits 6-4 = 000 → frame method = SegmentIndex (bit 6 = 0!)
    //   bit 3 (T) = 0 → explicit target datum
    //   bit 2 (P) = 1 → no displacement
    //   bits 1-0 = 00 → target method = SegmentIndex
    // 0x04 = 0000_0100
    //
    // NOTE: fix_data bit 6 = 0 here.  The old buggy code would read this as
    // M=0 (self-relative) instead of the correct M=1 from byte `b`.
    d.push(0x04u8);
    push_index(&mut d, 1); // frame datum: segment 1
    push_index(&mut d, 1); // target datum: segment 1
    push_record(&mut out, 0x9C, &d); // FIXUPP (16-bit)

    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse failed");
    let text = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("no _TEXT");
    let relocs: Vec<_> = text.relocations().collect();
    assert_eq!(relocs.len(), 1);
    let (offset, reloc) = &relocs[0];
    assert_eq!(*offset, 0, "fixup at byte offset 0");
    // With M=1, this must be SectionOffset (segment-relative), NOT Relative.
    assert_eq!(reloc.kind(), RelocationKind::SectionOffset);
    assert_eq!(reloc.size(), 16);

    // Segment-relative fixups targeting a segment should produce a Symbol target
    // (the synthetic section symbol) so consumers like objdiff can resolve them.
    match reloc.target() {
        RelocationTarget::Symbol(sym_idx) => {
            let sym = file.symbol_by_index(sym_idx).expect("section symbol lookup");
            assert_eq!(sym.kind(), SymbolKind::Section, "target should be a section symbol");
            assert_eq!(sym.name().unwrap_or(""), "_TEXT", "section symbol name");
        }
        other => panic!("expected Symbol target, got {:?}", other),
    }
}

#[test]
fn test_comdef_symbol() {
    let data = build_with_comdef();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();

    let buf = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "shared_buf")
        .expect("shared_buf not found");
    assert!(buf.is_common());
    assert_eq!(buf.size(), 100);
    assert_eq!(buf.address(), 0, "communal symbols have no address");

    let flag = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "shared_flag")
        .expect("shared_flag not found");
    assert!(flag.is_common());
    assert_eq!(flag.size(), 4);
}

#[test]
fn test_wkext_is_weak() {
    let data = build_with_wkext();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();

    let weak = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_weak_sym")
        .expect("_weak_sym not found");
    assert!(weak.is_weak(), "_weak_sym should be weak");

    let def = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_default_sym")
        .expect("_default_sym not found");
    assert!(!def.is_weak(), "_default_sym should not be weak");
}

#[test]
fn test_alias_symbol() {
    let data = build_with_alias();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();
    let alias_sym = syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "_foo_alias")
        .expect("_foo_alias not found");
    // Alias appears as an undefined/external-like symbol
    assert_eq!(alias_sym.kind(), SymbolKind::Unknown);
}

#[test]
fn test_lidata_expansion() {
    let data = build_with_lidata();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let section = file.sections().next().expect("no sections");
    assert_eq!(section.size(), 20);
    let expanded = section
        .uncompressed_data()
        .expect("uncompressed_data failed");
    assert_eq!(expanded.len(), 20);
    // All bytes should be 0xCC (fill pattern repeated 5×4 = 20 bytes)
    assert!(
        expanded.iter().all(|&b| b == 0xCC),
        "LIDATA expansion mismatch: {:?}",
        &expanded[..]
    );
}

#[test]
fn test_ledata_content() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let text = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("no _TEXT");
    // Single contiguous LEDATA chunk → data() should succeed
    let raw = text.data().expect("data() failed");
    assert_eq!(raw.len(), 8);
    assert_eq!(raw[0], 0xC3); // RET
}

#[test]
fn test_dynamic_symbols_empty() {
    // dynamic_symbols() should yield nothing (OMF has no dynamic symbol table)
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    assert_eq!(file.dynamic_symbols().count(), 0);
}

#[test]
fn test_comdats_empty_for_plain_object() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    assert_eq!(file.comdats().count(), 0);
}

#[test]
fn test_section_kind_text() {
    use object::SectionKind;
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let text = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("no _TEXT");
    assert_eq!(text.kind(), SectionKind::Text);
}

#[test]
fn test_section_kind_data() {
    use object::SectionKind;
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let data_sec = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_DATA")
        .expect("no _DATA");
    // _DATA with class DATA maps to Data or UninitializedData
    assert!(
        matches!(
            data_sec.kind(),
            SectionKind::Data | SectionKind::UninitializedData | SectionKind::ReadOnlyData
        ),
        "unexpected kind: {:?}",
        data_sec.kind()
    );
}

#[test]
fn test_symbol_by_index() {
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let syms: Vec<_> = file.symbols().collect();
    assert!(!syms.is_empty());
    let idx = syms[0].index();
    let looked_up = file.symbol_table().unwrap().symbol_by_index(idx).unwrap();
    assert_eq!(
        looked_up.name().unwrap(),
        syms[0].name().unwrap()
    );
}

#[test]
fn test_section_by_index() {
    use object::SectionIndex;
    let data = build_minimal_16bit();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    // Section indices are 1-based in OMF
    let sec = file.section_by_index(SectionIndex(1)).expect("section 1 not found");
    assert_eq!(sec.name().unwrap(), "_TEXT");
}

#[test]
fn test_zero_length_record_rejected() {
    // A record with length=0 is invalid (no room for checksum byte).
    let mut data = Vec::new();
    data.push(0x80); // THEADR
    data.push(0x00); // length low = 0
    data.push(0x00); // length high = 0
    // No data, no checksum
    let result = object::File::parse(data.as_slice());
    assert!(result.is_err(), "zero-length record should be rejected");
}

#[test]
fn test_comdat_kind() {
    // Build a minimal COMDAT record to verify ComdatKind mapping.
    let mut out = Vec::new();
    theadr(&mut out, b"comdat.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 4, 1, 2);
    // PUBDEF so COMDAT resolver can find a symbol
    pubdef(&mut out, 0, 1, &[(b"_inline_fn", 0)]);
    // COMDAT record (0xC2):
    // The attributes byte encodes:
    //   bits 7-4 (high nibble): selection — 0=Explicit, 1=UseAny, 2=SameSize, 3=ExactMatch
    //   bits 3-0 (low nibble):  allocation type — 0=Explicit (has public base), others=no base
    // We want UseAny (high nibble=1) with no public base (low nibble=1).
    // Record layout: flags, attributes, align_index, data_offset(16-bit), type_index,
    //   [if alloc==0: group_idx, seg_idx, [frame]], name_index (into LNAMES), data...
    let mut cd = Vec::new();
    cd.push(0x00); // flags
    cd.push(0x11); // attributes: high nibble=1 (UseAny), low nibble=1 (non-explicit, no base)
    cd.push(0x05); // align/segment index = 5 → DWord alignment
    cd.push(0x00); cd.push(0x00); // data_offset = 0 (16-bit)
    push_index(&mut cd, 0); // type index = 0
    // (no public base since allocation_type = 1 ≠ 0)
    push_index(&mut cd, 1); // name index = 1 → names[0] = "_TEXT" (name lookup)
    // COMDAT content (empty — parser stores &data[offset..] which may be empty)
    push_record(&mut out, 0xC2, &cd);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse failed");
    let comdats: Vec<_> = file.comdats().collect();
    assert!(!comdats.is_empty(), "expected at least one COMDAT");
    // UseAny should map to ComdatKind::Any
    assert_eq!(comdats[0].kind(), ComdatKind::Any);
}

#[test]
fn test_big_segment_64kb() {
    // B-bit in ACBP: stored length 0 means 65536 bytes (full 64KB segment).
    let data = build_big_segment();
    let file = object::File::parse(data.as_slice()).expect("parse failed");
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 1);
    assert_eq!(
        sections[0].size(),
        0x10000,
        "B-bit segment should be 65536 bytes"
    );
}

/// Build a 32-bit OMF object where a FIXUPP32 immediately follows a COMDAT32
/// record with no intervening LEDATA. This exercises the real-world pattern
/// seen in Borland/Watcom objects (e.g., UTRACKER.OBJ).
fn build_comdat_with_fixupp() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"comdat_fixupp.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef32(&mut out, 0x61, 16, 1, 2); // 32-bit code segment
    // EXTDEF: _target (external index 1)
    extdef(&mut out, &[b"_target"]);
    // PUBDEF32 so the COMDAT name resolver can find a symbol
    pubdef32(&mut out, 0, 1, &[(b"_inline_fn", 0)]);

    // COMDAT32 (0xC3): UseAny, DWord-aligned, inline CALL rel32 data.
    // Attribute byte: high nibble=1 (UseAny), low nibble=1 (non-explicit, no public base).
    let mut cd = Vec::new();
    cd.push(0x00); // flags
    cd.push(0x11); // attributes: UseAny, non-explicit (no public base field follows)
    cd.push(0x05); // align/segment index = 5 → DWord alignment
    cd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data_offset = 0 (32-bit)
    push_index(&mut cd, 0); // type index = 0
    push_index(&mut cd, 1); // name index = 1 → LNAMES[0] = "_TEXT"
    // Inline COMDAT data: CALL rel32 with a zero displacement placeholder
    cd.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    push_record(&mut out, 0xC3, &cd); // COMDAT32

    // FIXUPP32 (0x9D) immediately after COMDAT32 — no LEDATA in between.
    // LOCAT byte 1: 0xA4 = 1_0_1001_00
    //   bit 7=1 (FIXUP marker), bit 6=0 (M=0, self-relative),
    //   bits 5-2=1001 (location=9 = Offset32), bits 1-0=00 (offset_hi=0)
    // LOCAT byte 2: 0x01 — low byte of offset within the data block (points to displacement)
    // fix_data 0x26: F=0, frame=ExternalIndex(010), T=0, P=1, target=ExternalIndex(10)
    let mut fd = Vec::new();
    fd.push(0xA4u8); // LOCAT high byte
    fd.push(0x01u8); // LOCAT low byte (offset=1 within data block)
    fd.push(0x26u8); // fix_data
    push_index(&mut fd, 1); // frame datum: ext 1 (_target)
    push_index(&mut fd, 1); // target datum: ext 1 (_target)
    push_record(&mut out, 0x9D, &fd); // FIXUPP32

    modend(&mut out);
    out
}

#[test]
fn test_comdat_followed_by_fixupp_parses_without_error() {
    // A FIXUPP32 immediately following a COMDAT32 (no LEDATA in between) must
    // parse without returning an error.  The fixup is stored on the COMDAT and
    // merged into the synthetic COMDAT segment during promotion.  This
    // reproduces the pattern seen in real Borland/Watcom OBJ files.
    use object::RelocationKind;

    let data = build_comdat_with_fixupp();
    let mut file = object::File::parse(data.as_slice())
        .expect("COMDAT32 followed by FIXUPP32 should parse without error");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }
    // COMDAT entry should still be present and accessible
    assert!(file.comdats().count() > 0, "expected at least one COMDAT entry");
    // The FIXUPP should now produce a relocation on the COMDAT section.
    let total_relocs: usize = file.sections().map(|s| s.relocations().count()).sum();
    assert_eq!(total_relocs, 1, "COMDAT FIXUPP should produce one relocation");

    // Find the COMDAT section and verify the relocation properties.
    let comdat_section = file.sections().find(|s| {
        s.relocations().count() > 0
    }).expect("should have a section with relocations");
    let (offset, reloc) = comdat_section.relocations().next().unwrap();
    assert_eq!(offset, 1, "relocation offset should be 1 (after CALL opcode)");
    assert_eq!(reloc.kind(), RelocationKind::Relative, "self-relative fixup");
    assert_eq!(reloc.size(), 32, "Offset32 fixup size");
}

// ---------------------------------------------------------------------------
// COMDEF VIRDEF data type (0x01..0x5F = segment index)
// ---------------------------------------------------------------------------

/// Build an OMF with a COMDEF record using VIRDEF data types.
///
/// Per Borland's OMF extension, data type values 0x01..0x5F are VIRDEF
/// records: the data_type byte is a 1-based segment index, followed by
/// an encoded communal length (like NEAR COMDEF format).
fn build_comdef_virdef_type() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"virdef_comdef.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);

    // SEGDEF32: segment 1 = _TEXT, class CODE
    segdef32(&mut out, 0x61, 0, 1, 2);

    // COMDEF record with data_type = 0x01 → VIRDEF referencing segment 1 (_TEXT).
    // Format: name | type_index | data_type(=seg_idx) | encoded_length
    let mut d = Vec::new();
    push_string(&mut d, b"_inline_fn");
    push_index(&mut d, 0); // type index
    d.push(0x01u8); // data_type = VIRDEF, segment 1 (_TEXT)
    d.push(0x40); // encoded length = 0x40 (64 bytes)

    push_record(&mut out, 0xB0, &d); // COMDEF
    modend(&mut out);
    out
}

#[test]
fn test_comdef_virdef_data_type_parses_correctly() {
    // COMDEF records with VIRDEF data types (0x01..0x5F) use the byte as a
    // segment index.  The communal length is an encoded value that follows.
    let data = build_comdef_virdef_type();
    let file = object::File::parse(data.as_slice())
        .expect("COMDEF with VIRDEF data type should parse without error");

    // Locate the communal symbol
    let sym = file
        .symbols()
        .find(|s| s.name() == Ok("_inline_fn"))
        .expect("_inline_fn symbol not found");

    // size() must reflect the encoded length (0x40), not the data_type byte (0x01)
    assert_eq!(sym.size(), 0x40, "_inline_fn size should be 0x40 (encoded length)");
}

// ---------------------------------------------------------------------------
// SEGDEF reserved alignment (ACBP A-field = 7)
// ---------------------------------------------------------------------------

/// Build an OMF with a SEGDEF whose ACBP alignment bits are 7 (reserved).
///
/// Per the OMF spec alignment 7 is reserved. Real Watcom/Borland tools may
/// emit it; we should treat it as byte alignment rather than return an error.
fn build_segdef_reserved_alignment() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"reserved_align.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);

    // ACBP: alignment=7 (bits 7-5 = 111 → 0xE0), combination=0, use32=0
    // So ACBP = 0xE0 | 0x00 = 0xE0
    let acbp: u8 = 0xE0;
    segdef(&mut out, acbp, 4, 1, 2);

    modend(&mut out);
    out
}

#[test]
fn test_segdef_reserved_alignment_parses_without_error() {
    // A SEGDEF with reserved ACBP alignment bits (7) must parse without error.
    // It should be treated as byte alignment (safe fallback).
    let data = build_segdef_reserved_alignment();
    let file = object::File::parse(data.as_slice())
        .expect("SEGDEF with reserved alignment bits should parse without error");

    // One segment should be present with the correct size
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 1, "expected one segment");
    assert_eq!(sections[0].size(), 4, "segment size should be 4");
    // Alignment should fall back to byte (1)
    assert_eq!(sections[0].align(), 1, "reserved alignment should fall back to 1");
}

// ---------------------------------------------------------------------------
// Bad checksum tolerance
// ---------------------------------------------------------------------------

/// Build an OMF file where one record carries a deliberately wrong (non-zero)
/// checksum byte that does not satisfy the OMF spec's byte-sum constraint.
///
/// Some Borland/Watcom tools emit incorrect checksums. We must:
/// 1. Still detect the file as OMF (is_omf must return true), and
/// 2. Parse the records with valid checksums while silently skipping those
///    with bad checksums (so the file-level parse still succeeds).
fn build_bad_checksum() -> Vec<u8> {
    let mut out = Vec::new();
    // THEADR with correct (zero) checksum — used by is_omf() for detection
    theadr(&mut out, b"bad_csum.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // SEGDEF with a deliberate bad checksum: emit it manually and corrupt the
    // checksum byte so that the sum-of-all-bytes != 0.
    // This record should be silently skipped by parse_records.
    {
        let mut seg_data = Vec::new();
        seg_data.push(0x61u8); // ACBP: DWord alignment + use32
        seg_data.push(0x04u8); // length lo
        seg_data.push(0x00u8); // length hi
        push_index(&mut seg_data, 1); // seg name index
        push_index(&mut seg_data, 2); // class name index
        push_index(&mut seg_data, 0); // overlay
        // Build the record with type 0x98 (SEGDEF) but a wrong checksum
        let len = (seg_data.len() + 1) as u16;
        out.push(0x98u8); // SEGDEF
        out.push(len as u8);
        out.push((len >> 8) as u8);
        out.extend_from_slice(&seg_data);
        out.push(0x42u8); // deliberately wrong checksum (not 0, sum != 0)
    }
    modend(&mut out);
    out
}

#[test]
fn test_bad_checksum_file_detected_as_omf() {
    // Even when a non-THEADR record has a wrong checksum, is_omf() must still
    // return true because it only examines the first (THEADR) record.
    let data = build_bad_checksum();
    // File::parse goes through FileKind detection; must not return "Unknown file magic"
    let result = object::File::parse(data.as_slice());
    // The file should parse; the bad-checksum SEGDEF is silently skipped so we
    // get 0 sections (the segment was not registered) but no error.
    assert!(
        result.is_ok(),
        "File with bad-checksum record should still parse: {:?}",
        result.err()
    );
}

#[test]
fn test_bad_checksum_record_skipped_not_fatal() {
    // A record with a bad checksum must be silently skipped; the rest of the
    // file (LNAMES, MODEND) must still parse without error.
    let data = build_bad_checksum();
    let file = object::File::parse(data.as_slice())
        .expect("Bad-checksum record should not abort parse");
    // The bad-checksum SEGDEF was skipped → 0 sections
    assert_eq!(
        file.sections().count(),
        0,
        "Bad-checksum SEGDEF should be skipped, yielding 0 sections"
    );
}

// ---------------------------------------------------------------------------
// PUBDEF symbol size inference
// ---------------------------------------------------------------------------

/// Build an OMF with three PUBDEF symbols at known offsets in a 32-byte segment.
///
/// Layout:
///   _func_a  offset 0   → size = 12 (distance to _func_b)
///   _func_b  offset 12  → size = 8  (distance to _func_c)
///   _func_c  offset 20  → size = 12 (segment_length - 20 = 32 - 20)
fn build_multi_pubdef_sizes() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"sizes.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // 32-byte 32-bit code segment
    segdef32(&mut out, 0x61, 32, 1, 2);
    // Three public symbols at distinct offsets (deliberately out of order to test sort)
    pubdef32(&mut out, 0, 1, &[
        (b"_func_c", 20),
        (b"_func_a", 0),
        (b"_func_b", 12),
    ]);
    modend(&mut out);
    out
}

#[test]
fn test_pubdef_symbol_sizes_inferred() {
    // PUBDEF symbol sizes must be inferred from adjacent symbols within the
    // segment. This is required for consumers like objdiff that use size() to
    // determine how many bytes of section data to disassemble.
    let data = build_multi_pubdef_sizes();
    let file = object::File::parse(data.as_slice()).expect("parse failed");

    let syms: Vec<_> = file.symbols().collect();

    let find = |name: &str| {
        syms.iter()
            .find(|s| s.name().unwrap_or("") == name)
            .unwrap_or_else(|| panic!("{} not found", name))
            .size()
    };

    assert_eq!(find("_func_a"), 12, "_func_a should span 0..12");
    assert_eq!(find("_func_b"), 8,  "_func_b should span 12..20");
    assert_eq!(find("_func_c"), 12, "_func_c should span 20..32 (segment end)");
}

// ---------------------------------------------------------------------------
// Regression: SEGDEF (0x98) with use32=true must use 2-byte length field
// ---------------------------------------------------------------------------

/// Build a minimal OMF object that uses SEGDEF (record type 0x98, not SEGDEF32)
/// with the ACBP D-bit (use32) set to 1.
///
/// Many Borland/Watcom tools emit SEGDEF 0x98 records with use32=true for
/// 32-bit code segments that fit in 16-bit length.  The ACBP D-bit controls
/// addressing mode (USE32 vs USE16) — it does NOT widen the length field.
/// Only the *record type* (0x99 = SEGDEF32) should widen the length to 4 bytes.
fn build_segdef_use32_in_16bit_record() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"use32_16bit.c");
    // LNAMES: "" | "_TEXT" | "CODE"
    lnames(&mut out, &[b"", b"_TEXT", b"CODE"]);
    // SEGDEF 0x98 with ACBP=0xa1:
    //   alignment = 5 (DWord), combination = 0 (Private), use32 = 1, big = 0
    //   length = 0x0010 (16 bytes) — 2-byte field in the record
    // Old buggy parser would read 4 bytes for the length, consuming the index
    // bytes, and then fail with "Invalid class name index".
    segdef(&mut out, 0xa1, 0x0010, 2, 3); // seg_name=2→"_TEXT", class=3→"CODE"
    // MODEND
    push_record(&mut out, 0x8a, &[0x00]);
    out
}

#[test]
fn test_segdef_use32_in_16bit_record_parses() {
    let data = build_segdef_use32_in_16bit_record();
    let file = object::File::parse(data.as_slice())
        .expect("SEGDEF(0x98) with use32=true must parse without error");

    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 1, "should have one section");
    assert_eq!(sections[0].name().unwrap(), "_TEXT");
    assert_eq!(sections[0].size(), 0x10, "segment length must be 0x10, not a 4-byte misread");
    // Confirm the D-bit is correctly reflected in the section flags
    if let object::SectionFlags::Omf { use32 } = sections[0].flags() {
        assert!(use32, "D-bit in ACBP should set use32=true on the section");
    }
}

// ---------------------------------------------------------------------------
// Real-file regression tests (UTRACKER.OBJ — Borland/Watcom 32-bit OMF)
// ---------------------------------------------------------------------------

/// End-to-end regression test for a real Borland/Watcom OBJ file.
///
/// Covers all of the compatibility fixes added for real-world OMF files:
/// - Correct detection (no "Unknown file magic")
/// - Architecture I386 (not Unknown) for all OMF files
/// - PUBDEF symbols get kind=Text + inferred non-zero sizes
/// - Section mapping: symbols land in SectionIndex(1) (_TEXT)
#[test]
fn test_utracker_obj_regression() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/UTRACKER.OBJ");
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return, // file not present in this environment; skip silently
    };

    let file = object::File::parse(data.as_slice()).expect("UTRACKER.OBJ should parse as OMF");

    // Basic format checks
    assert_eq!(file.format(), BinaryFormat::Omf, "must be detected as OMF");
    assert_eq!(file.architecture(), Architecture::I386, "all OMF files are I386");

    // _TEXT section is SectionIndex(1) with Text kind and non-zero size
    let text_section = file
        .section_by_index(object::SectionIndex(1))
        .expect("SectionIndex(1) must exist");
    assert_eq!(text_section.name().unwrap(), "_TEXT");
    assert!(text_section.size() > 0, "_TEXT must have non-zero size");

    // All PUBDEF symbols in _TEXT must have kind=Text and non-zero inferred size
    let text_syms: Vec<_> = file
        .symbols()
        .filter(|s| {
            !s.is_undefined()
                && s.section() == SymbolSection::Section(object::SectionIndex(1))
        })
        .collect();

    assert!(
        !text_syms.is_empty(),
        "must have at least one defined symbol in _TEXT"
    );
    for sym in &text_syms {
        assert_eq!(
            sym.kind(),
            SymbolKind::Text,
            "PUBDEF in _TEXT must have kind=Text, got {:?} for {:?}",
            sym.kind(),
            sym.name().unwrap_or("?")
        );
        assert!(
            sym.size() > 0,
            "PUBDEF symbol {:?} must have inferred non-zero size",
            sym.name().unwrap_or("?")
        );
    }

    // Spot-check a known symbol (constructor)
    let ctor = text_syms
        .iter()
        .find(|s| s.name().unwrap_or("") == "W?$ct:UnitTrackerClass$n(i)_");
    if let Some(ctor) = ctor {
        assert!(ctor.size() > 0, "constructor must have non-zero size");
    }
}

// ---------------------------------------------------------------------------
// COMDAT synthetic-section exposure
// ---------------------------------------------------------------------------

/// Build a minimal OMF32 object where a COMDAT32 record's public-name LNAMES
/// entry matches the PUBDEF symbol name.  This exercises `create_comdat_segments()`:
/// the COMDAT's 5-byte inline body should become a synthetic section and the
/// matching PUBDEF symbol should be updated to point at it.
///
/// Layout:
/// * SEGDEF32 — a placeholder code segment (length=0, no class).  Needed so
///   that the PUBDEF32 can reference a valid segment index.
/// * PUBDEF32 — defines "_InlineFn" in segment 1 at offset 0.
/// * COMDAT32 — name_index=1 → LNAMES[0]="_InlineFn"; body = 5 NOP bytes.
fn build_comdat_with_named_inline() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"inline.c");

    // LNAMES: index 1 = "_InlineFn".  The COMDAT record references this index
    // as its "public name", and parse_comdat matches it against PUBDEF symbols.
    lnames(&mut out, &[b"_InlineFn"]);

    // SEGDEF32: Use32 | Paragraph alignment (0x61), length=0, no name (idx=0),
    // no class (idx=0).  A length of 0 gives us a valid but empty code segment.
    segdef32(&mut out, 0x61, 0, 0, 0);

    // PUBDEF32: defines "_InlineFn" in segment 1 at offset 0.
    pubdef32(&mut out, 0, 1, &[(b"_InlineFn", 0)]);

    // COMDAT32 (0xC3):
    //   attributes: high nibble = 1 (UseAny), low nibble = 1 (non-explicit, no public base).
    //   align/seg field = 5 → DWord alignment.
    //   name_index = 1 → LNAMES[0] = "_InlineFn".
    //   body: 5 NOP bytes.
    let mut cd = Vec::new();
    cd.push(0x00); // flags
    cd.push(0x11); // attributes: UseAny, no public base
    cd.push(0x05); // align/segment = 5 → DWord
    cd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data_offset (32-bit) = 0
    push_index(&mut cd, 0); // type_index = 0
    push_index(&mut cd, 1); // name_index = 1 → "_InlineFn"
    cd.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90]); // 5 × NOP
    push_record(&mut out, 0xC3, &cd);

    modend(&mut out);
    out
}

/// Verify that COMDAT records with inline data are exposed as regular sections.
///
/// Watcom places inline / linkonce functions inside COMDAT records. Before
/// `create_comdat_segments()`, these were only accessible via `file.comdats()`
/// and invisible to `file.sections()`. Now every non-empty COMDAT must appear
/// as an extra section with `SectionKind::Text`, and the matching symbol must
/// have kind=Text and a non-zero size.
#[test]
fn test_comdat_exposed_as_section() {
    let data = build_comdat_with_named_inline();
    let mut file = object::File::parse(data.as_slice()).expect("parse failed");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }

    // Sections: one real (empty placeholder SEGDEF) + one synthetic COMDAT.
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 2, "expected SEGDEF + synthetic COMDAT = 2 sections, got {}", sections.len());

    // The synthetic COMDAT section is the second one.
    let comdat_sec = &sections[1];
    assert_eq!(comdat_sec.kind(), object::SectionKind::Text, "synthetic COMDAT section must have kind=Text");
    assert_eq!(comdat_sec.size(), 5, "synthetic COMDAT section must be 5 bytes");
    assert_eq!(
        comdat_sec.data().unwrap(),
        &[0x90, 0x90, 0x90, 0x90, 0x90],
        "synthetic COMDAT section data must match the NOP sled"
    );

    // The symbol _InlineFn must now be linked to the synthetic COMDAT section.
    let sym = file
        .symbols()
        .find(|s| s.name().unwrap_or("") == "_InlineFn")
        .expect("_InlineFn symbol must exist");
    assert_eq!(sym.kind(), SymbolKind::Text, "_InlineFn must have kind=Text");
    assert_eq!(sym.size(), 5, "_InlineFn must have size=5 (the inline COMDAT body)");
}

// ---------------------------------------------------------------------------
// COMDAT continuation records (flags bit 1)
// ---------------------------------------------------------------------------
//
// When a COMDAT body is larger than one record, the compiler emits a
// continuation record with flags bit 1 set.  Continuation records have a
// shortened header (just flags + attributes, then data).  The data must be
// appended to the previous COMDAT entry.

fn build_comdat_with_continuation() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"cont.c");

    lnames(&mut out, &[b"_BigInline"]);
    segdef32(&mut out, 0x61, 0, 0, 0);
    pubdef32(&mut out, 0, 1, &[(b"_BigInline", 0)]);

    // First COMDAT32 record: flags=0x00 (no continuation), 3 bytes of body.
    let mut cd1 = Vec::new();
    cd1.push(0x00); // flags: not continuation
    cd1.push(0x11); // attributes: UseAny, no public base
    cd1.push(0x05); // align/segment = 5 → DWord
    cd1.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data_offset (32-bit)
    push_index(&mut cd1, 0); // type_index
    push_index(&mut cd1, 1); // name_index → "_BigInline"
    cd1.extend_from_slice(&[0x55, 0x89, 0xE5]); // push ebp; mov ebp, esp
    push_record(&mut out, 0xC3, &cd1);

    // Continuation COMDAT32: flags=0x02 (continuation bit set).
    // Only flags + attributes, then raw data — no seg/offset/type/name fields.
    let mut cd2 = Vec::new();
    cd2.push(0x02); // flags: continuation
    cd2.push(0x11); // attributes (must be present but content is irrelevant)
    cd2.extend_from_slice(&[0x90, 0x90, 0x5D, 0xC3]); // nop; nop; pop ebp; ret
    push_record(&mut out, 0xC3, &cd2);

    modend(&mut out);
    out
}

#[test]
fn test_comdat_continuation_merges_data() {
    let data = build_comdat_with_continuation();
    let mut file = object::File::parse(data.as_slice()).expect("parse failed");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }

    // Should have 2 sections: the empty SEGDEF + the synthetic COMDAT.
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 2, "expected SEGDEF + COMDAT = 2 sections");

    let comdat_sec = &sections[1];
    assert_eq!(
        comdat_sec.size(),
        7,
        "COMDAT section must contain 3 + 4 = 7 bytes from initial + continuation"
    );
    assert_eq!(
        comdat_sec.uncompressed_data().unwrap().as_ref(),
        &[0x55, 0x89, 0xE5, 0x90, 0x90, 0x5D, 0xC3],
        "COMDAT data must be the concatenation of both records"
    );

    let sym = file
        .symbols()
        .find(|s| s.name().unwrap_or("") == "_BigInline")
        .expect("_BigInline symbol must exist");
    assert_eq!(sym.size(), 7, "_BigInline must have size=7 (combined body)");
}

// ---------------------------------------------------------------------------
// LEDATA updates segment length when SEGDEF length = 0
// ---------------------------------------------------------------------------
//
// Watcom's "one segment per function" COMDAT model emits SEGDEF records with
// length=0.  The actual code bytes arrive in a LEDATA record that follows.
// `section.size()` must reflect the LEDATA content length, not the SEGDEF 0.

fn build_segdef_zero_length_with_ledata() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"dynavec_model.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);

    // SEGDEF32 with length = 0.  Watcom emits this for every COMDAT function
    // and relies on LEDATA records to define the actual content size.
    // acbp = 0x61 → DWord-aligned (100), combination=Public (011), use32=1 (1)
    segdef32(&mut out, 0x61, 0, 1, 2);

    // PUBDEF32: symbol "_DynaVec_Insert" at offset 0 in segment 1
    pubdef32(&mut out, 0, 1, &[(b"_DynaVec_Insert", 0)]);

    // LEDATA (16-bit record type 0xA0): fills segment 1 with 6 bytes of code.
    // The segment length must be inferred from this data.
    ledata(&mut out, 1, 0, &[0x55, 0x89, 0xE5, 0x90, 0x90, 0xC3]);

    modend(&mut out);
    out
}

#[test]
fn test_ledata_updates_zero_length_segment() {
    // When a SEGDEF has length=0 and a LEDATA record provides actual bytes,
    // section.size() must return the LEDATA data length, not 0.
    // This is the Watcom "one segment per COMDAT" model used in DYNAVEC.OBJ.
    let data = build_segdef_zero_length_with_ledata();
    let file = object::File::parse(data.as_slice()).expect("parse failed");

    let section = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "_TEXT")
        .expect("_TEXT section not found");

    assert_eq!(
        section.size(),
        6,
        "section.size() should equal the LEDATA byte count (6), not the SEGDEF length (0)"
    );
    assert_eq!(
        section.data().unwrap(),
        &[0x55, 0x89, 0xE5, 0x90, 0x90, 0xC3],
        "section data must match the LEDATA content"
    );

    // The PUBDEF symbol should also have an inferred size from the section.
    let sym = file
        .symbols()
        .find(|s| s.name().unwrap_or("") == "_DynaVec_Insert")
        .expect("_DynaVec_Insert symbol not found");
    assert_eq!(sym.size(), 6, "_DynaVec_Insert size should be inferred as 6");
}

// ---------------------------------------------------------------------------
// COMDAT before PUBDEF — ordering bug regression
// ---------------------------------------------------------------------------

/// Build a 32-bit OMF where the COMDAT32 record appears **before** the
/// matching PUBDEF32.  This is the ordering used by DYNAVEC.OBJ and similar
/// Watcom/Borland objects.
///
/// When `parse_comdat()` runs, `self.symbols` does not yet contain `_InlineFn`
/// (it comes from the later PUBDEF32 record), so `symbol_index` stays `None`.
/// `create_comdat_segments()` must re-resolve it in a second pass.
fn build_comdat_before_pubdef() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"dynavec_sim.c");

    // LNAMES: index 1 = "_InlineFn"
    lnames(&mut out, &[b"_InlineFn"]);

    // SEGDEF32: empty placeholder code segment (length=0).
    segdef32(&mut out, 0x61, 0, 0, 0);

    // COMDAT32 *first* — no matching PUBDEF in self.symbols yet.
    let mut cd = Vec::new();
    cd.push(0x00); // flags
    cd.push(0x11); // attributes: UseAny, no public base
    cd.push(0x05); // align/segment = 5 → DWord alignment
    cd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data_offset (32-bit) = 0
    push_index(&mut cd, 0); // type_index = 0
    push_index(&mut cd, 1); // name_index = 1 → "_InlineFn"
    cd.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90]); // 5 × NOP
    push_record(&mut out, 0xC3, &cd); // COMDAT32

    // PUBDEF32 *after* COMDAT32 — this is the ordering bug scenario.
    pubdef32(&mut out, 0, 1, &[(b"_InlineFn", 0)]);

    modend(&mut out);
    out
}

#[test]
fn test_comdat_before_pubdef_symbol_linked() {
    // When COMDAT32 appears before PUBDEF32, `create_comdat_segments()` must
    // re-resolve the COMDAT's `symbol_index` in a second pass so that:
    //   (a) the synthetic section is visible via `file.sections()`, and
    //   (b) the matching symbol is linked to it with kind=Text and correct size.
    let data = build_comdat_before_pubdef();
    let mut file = object::File::parse(data.as_slice()).expect("parse failed");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }

    // Sections: 1 real (empty SEGDEF) + 1 synthetic COMDAT = 2.
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(
        sections.len(),
        2,
        "expected SEGDEF + synthetic COMDAT = 2 sections, got {}",
        sections.len()
    );

    let comdat_sec = &sections[1];
    assert_eq!(
        comdat_sec.kind(),
        object::SectionKind::Text,
        "synthetic COMDAT section must have kind=Text"
    );
    assert_eq!(comdat_sec.size(), 5, "synthetic COMDAT section must be 5 bytes");
    assert_eq!(
        comdat_sec.data().unwrap(),
        &[0x90, 0x90, 0x90, 0x90, 0x90],
        "synthetic COMDAT section data must be 5 NOPs"
    );

    // _InlineFn must be linked to the synthetic COMDAT section.
    let sym = file
        .symbols()
        .find(|s| s.name().unwrap_or("") == "_InlineFn")
        .expect("_InlineFn symbol must exist");
    assert_eq!(sym.kind(), SymbolKind::Text, "_InlineFn must have kind=Text");
    assert_eq!(sym.size(), 5, "_InlineFn must have size=5 (the inline COMDAT body)");
}


/// Build a minimal OMF with a COMDAT32 function but NO matching PUBDEF record.
/// This models DYNAVEC.OBJ where Watcom emits COMDAT32 as the sole definition
/// (no separate PUBDEF).  The parser must synthesise a Public symbol so the
/// function is visible in objdiff (sym.section.is_some() && sym.size > 0).
fn build_comdat_no_pubdef() -> Vec<u8> {
    let mut out = Vec::new();
    theadr(&mut out, b"dynavec_nopub.c");
    // LNAMES: 1=_TEXT, 2=CODE, 3=_DynVec_Insert (the COMDAT public name)
    lnames(&mut out, &[b"_TEXT", b"CODE", b"_DynVec_Insert"]);
    // COMDAT32 (0xC3): UseAny selection, alloc=1, Byte align, offset=0, type=0
    //   name_index = 3 → "_DynVec_Insert"
    //   inline body = 5 bytes of x86 code
    let mut d = Vec::new();
    d.push(0x00u8); // flags
    d.push(0x11u8); // attributes: (UseAny<<4) | alloc_type_1
    d.push(0x01u8); // align/seg field = 1 → Byte alignment (value 1..=7)
    d.extend_from_slice(&0u32.to_le_bytes()); // data offset (32-bit, COMDAT32)
    d.push(0x00u8); // type index
    push_index(&mut d, 3); // public name index → "_DynVec_Insert"
    d.extend_from_slice(&[0x55u8, 0x89, 0xE5, 0x90, 0xC3]); // 5-byte body
    push_record(&mut out, 0xC3, &d);
    modend(&mut out);
    out
}

#[test]
fn test_comdat_without_pubdef_has_visible_symbol() {
    // DYNAVEC.OBJ defines functions only via COMDAT32, no PUBDEF records.
    // create_comdat_segments() must synthesise a Public symbol for each such
    // COMDAT so that objdiff can see the function (section.is_some && size > 0).
    let data = build_comdat_no_pubdef();
    let mut file = object::File::parse(data.as_slice()).expect("parse failed");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }

    // The single merged "COMDAT" section must exist with non-zero size.
    let comdat_section = file
        .sections()
        .find(|s| s.name().unwrap_or("") == "COMDAT")
        .expect("expected a merged 'COMDAT' section");
    assert!(
        comdat_section.size() > 0,
        "COMDAT section must have non-zero size, got {}",
        comdat_section.size()
    );

    // At least one visible symbol must exist (section assigned + size > 0).
    let visible: Vec<_> = file
        .symbols()
        .filter(|s| s.section_index().is_some() && s.size() > 0)
        .collect();
    assert!(
        !visible.is_empty(),
        "expected a visible symbol synthesised from COMDAT (no PUBDEF), \
         but got 0 visible symbols; sections = {:?}",
        file.sections()
            .map(|s| (s.name().unwrap_or("?").to_string(), s.size()))
            .collect::<Vec<_>>()
    );

    let sym = visible
        .iter()
        .find(|s| s.name().unwrap_or("") == "_DynVec_Insert")
        .expect("expected synthesised symbol named '_DynVec_Insert'");
    assert_eq!(sym.size(), 5, "_DynVec_Insert must have size 5 (COMDAT body length)");
    assert_eq!(
        sym.kind(),
        SymbolKind::Text,
        "_DynVec_Insert must be a Text symbol (COMDAT in code segment)"
    );
}

// ---------------------------------------------------------------------------
// LINNUM (line number) tests
// ---------------------------------------------------------------------------

/// Build an OMF object with a LINNUM record and verify the parsed line numbers.
#[test]
fn omf_linnum_16bit() {
    let mut out = Vec::new();
    theadr(&mut out, b"linnum.c");
    // LNAMES: idx1=_TEXT, idx2=CODE
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // SEGDEF: segment 1 = _TEXT/CODE, use16, DWord alignment, 32 bytes
    segdef(&mut out, 0x60, 32, 1, 2);
    // LEDATA: fill segment 1 with some bytes
    ledata(&mut out, 1, 0, &[0xCC; 32]);
    // LINNUM for segment 1: (line, offset) pairs
    linnum(&mut out, 0, 1, &[(10, 0x00), (11, 0x04), (15, 0x0C), (20, 0x18)]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    assert_eq!(file.format(), BinaryFormat::Omf);

    // Access line numbers via the OMF-specific API.
    if let object::File::Omf(ref omf) = file {
        let lines = omf.segment_line_numbers(0);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], (10, 0x00));
        assert_eq!(lines[1], (11, 0x04));
        assert_eq!(lines[2], (15, 0x0C));
        assert_eq!(lines[3], (20, 0x18));
    } else {
        panic!("expected OMF file");
    }
}

/// LINNUM32: verify 32-bit line number offsets.
#[test]
fn omf_linnum_32bit() {
    let mut out = Vec::new();
    theadr(&mut out, b"linnum32.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // SEGDEF32: use32 (bit 0 of acbp), DWord alignment
    segdef32(&mut out, 0x61, 0x200, 1, 2);
    // LINNUM32 for segment 1
    linnum32(&mut out, 0, 1, &[(100, 0x00), (101, 0x10), (110, 0x100)]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(ref omf) = file {
        let lines = omf.segment_line_numbers(0);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], (100, 0x00));
        assert_eq!(lines[1], (101, 0x10));
        assert_eq!(lines[2], (110, 0x100));
    } else {
        panic!("expected OMF file");
    }
}

/// Multiple LINNUM records for the same segment accumulate entries.
#[test]
fn omf_linnum_multiple_records() {
    let mut out = Vec::new();
    theadr(&mut out, b"multi.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 64, 1, 2);
    ledata(&mut out, 1, 0, &[0x90; 64]);
    // Two separate LINNUM records for segment 1
    linnum(&mut out, 0, 1, &[(1, 0x00), (2, 0x08)]);
    linnum(&mut out, 0, 1, &[(3, 0x10), (4, 0x18)]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(ref omf) = file {
        let lines = omf.segment_line_numbers(0);
        assert_eq!(lines.len(), 4, "two LINNUM records should accumulate");
        assert_eq!(lines[0], (1, 0x00));
        assert_eq!(lines[3], (4, 0x18));
    } else {
        panic!("expected OMF file");
    }
}

/// No LINNUM records — segment_line_numbers returns an empty slice.
#[test]
fn omf_no_linnum() {
    let mut out = Vec::new();
    theadr(&mut out, b"noline.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef(&mut out, 0x60, 8, 1, 2);
    ledata(&mut out, 1, 0, &[0xCC; 8]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(ref omf) = file {
        assert!(omf.segment_line_numbers(0).is_empty());
    } else {
        panic!("expected OMF file");
    }
}

// ---------------------------------------------------------------------------
// LINSYM (COMDAT line numbers)
// ---------------------------------------------------------------------------

/// Build a LINSYM32 record (0xC5) associating line numbers with a COMDAT symbol.
fn linsym32(out: &mut Vec<u8>, name_index: u16, entries: &[(u16, u32)]) {
    let mut d = Vec::new();
    d.push(0x00); // flags
    push_index(&mut d, name_index);
    for &(line, offset) in entries {
        d.push(line as u8);
        d.push((line >> 8) as u8);
        d.push(offset as u8);
        d.push((offset >> 8) as u8);
        d.push((offset >> 16) as u8);
        d.push((offset >> 24) as u8);
    }
    push_record(out, 0xC5, &d);
}

/// Build a LINSYM record (0xC4) associating 16-bit line numbers with a COMDAT symbol.
fn linsym(out: &mut Vec<u8>, name_index: u16, entries: &[(u16, u16)]) {
    let mut d = Vec::new();
    d.push(0x00); // flags
    push_index(&mut d, name_index);
    for &(line, offset) in entries {
        d.push(line as u8);
        d.push((line >> 8) as u8);
        d.push(offset as u8);
        d.push((offset >> 8) as u8);
    }
    push_record(out, 0xC4, &d);
}

/// LINSYM32 line numbers are merged into the synthetic COMDAT segment.
#[test]
fn omf_linsym32_comdat() {
    let mut out = Vec::new();
    theadr(&mut out, b"linsym.c");
    // LNAMES: idx1="_InlineFn"
    lnames(&mut out, &[b"_InlineFn"]);
    // SEGDEF32: placeholder code segment
    segdef32(&mut out, 0x61, 0, 0, 0);
    // PUBDEF32: defines "_InlineFn" in segment 1
    pubdef32(&mut out, 0, 1, &[(b"_InlineFn", 0)]);
    // COMDAT32: UseAny, name_index=1
    let mut cd = Vec::new();
    cd.push(0x00); // flags
    cd.push(0x11); // attributes: UseAny, no public base
    cd.push(0x05); // align = DWord
    cd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data_offset (32-bit)
    push_index(&mut cd, 0); // type_index
    push_index(&mut cd, 1); // name_index = 1 → "_InlineFn"
    cd.extend_from_slice(&[0x55, 0x89, 0xE5, 0x90, 0xC3]); // 5-byte body
    push_record(&mut out, 0xC3, &cd);
    // LINSYM32 targeting same name index
    linsym32(&mut out, 1, &[(10, 0x00), (12, 0x03), (15, 0x04)]);
    modend(&mut out);

    let mut file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(omf) = &mut file {
        omf.merge_sections();
    }
    if let object::File::Omf(omf) = &file {
        // The COMDAT merges into the last segment (synthetic).
        // Line numbers should be on that merged segment.
        let seg_count = omf.raw_segments().len();
        assert!(seg_count >= 2, "expected at least 2 segments (real + synthetic COMDAT)");
        let comdat_seg = seg_count - 1; // last segment = merged COMDAT
        let lines = omf.segment_line_numbers(comdat_seg);
        assert_eq!(lines.len(), 3, "expected 3 LINSYM entries on COMDAT segment");
        assert_eq!(lines[0], (10, 0x00));
        assert_eq!(lines[1], (12, 0x03));
        assert_eq!(lines[2], (15, 0x04));
    } else {
        panic!("expected OMF file");
    }
}

/// Two COMDATs with LINSYM: offsets are adjusted when merged into one segment.
#[test]
fn omf_linsym32_two_comdats_merged() {
    let mut out = Vec::new();
    theadr(&mut out, b"two_comdats.c");
    // LNAMES: idx1="_FuncA", idx2="_FuncB"
    lnames(&mut out, &[b"_FuncA", b"_FuncB"]);
    // SEGDEF32: placeholder
    segdef32(&mut out, 0x61, 0, 0, 0);
    // PUBDEF32: both functions
    pubdef32(&mut out, 0, 1, &[(b"_FuncA", 0), (b"_FuncB", 0)]);

    // COMDAT32 #1: _FuncA, 4-byte body
    let mut cd = Vec::new();
    cd.push(0x00); cd.push(0x11); cd.push(0x05);
    cd.extend_from_slice(&[0x00; 4]); // data_offset
    push_index(&mut cd, 0); // type_index
    push_index(&mut cd, 1); // name_index = 1 → "_FuncA"
    cd.extend_from_slice(&[0x55, 0x89, 0xE5, 0xC3]); // 4-byte body
    push_record(&mut out, 0xC3, &cd);
    // LINSYM32 for _FuncA
    linsym32(&mut out, 1, &[(100, 0x00), (101, 0x02)]);

    // COMDAT32 #2: _FuncB, 6-byte body
    let mut cd2 = Vec::new();
    cd2.push(0x00); cd2.push(0x11); cd2.push(0x05);
    cd2.extend_from_slice(&[0x00; 4]);
    push_index(&mut cd2, 0);
    push_index(&mut cd2, 2); // name_index = 2 → "_FuncB"
    cd2.extend_from_slice(&[0x55, 0x89, 0xE5, 0x90, 0x90, 0xC3]); // 6-byte body
    push_record(&mut out, 0xC3, &cd2);
    // LINSYM32 for _FuncB
    linsym32(&mut out, 2, &[(200, 0x00), (201, 0x03)]);

    modend(&mut out);

    let mut file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(omf) = &mut file {
        omf.merge_sections();
    }
    if let object::File::Omf(omf) = &file {
        let seg_count = omf.raw_segments().len();
        let comdat_seg = seg_count - 1;
        let lines = omf.segment_line_numbers(comdat_seg);
        // _FuncA (4 bytes) is at offset 0, _FuncB (6 bytes) at offset 4.
        // _FuncA lines: (100, 0), (101, 2) — no adjustment
        // _FuncB lines: (200, 0+4=4), (201, 3+4=7)
        assert_eq!(lines.len(), 4, "expected 4 merged LINSYM entries");
        assert_eq!(lines[0], (100, 0x00));
        assert_eq!(lines[1], (101, 0x02));
        assert_eq!(lines[2], (200, 0x04)); // offset adjusted by _FuncA size (4)
        assert_eq!(lines[3], (201, 0x07)); // 3 + 4 = 7
    } else {
        panic!("expected OMF file");
    }
}

// ---------------------------------------------------------------------------
// Segment merging (Watcom one-segment-per-function fixup)
// ---------------------------------------------------------------------------

/// Three _TEXT/CODE segments with different sizes, symbols, and line numbers
/// are merged into a single _TEXT section.
#[test]
fn omf_merge_same_name_segments() {
    use object::{Object, ObjectSection, ObjectSymbol};

    let mut out = Vec::new();
    theadr(&mut out, b"merge.c");
    // LNAMES: idx1=_TEXT, idx2=CODE, idx3=_DATA, idx4=DATA
    lnames(&mut out, &[b"_TEXT", b"CODE", b"_DATA", b"DATA"]);

    // Three _TEXT/CODE segments (indices 1, 2, 3):
    //   seg 1: 8 bytes, symbol func1 at offset 0
    //   seg 2: 12 bytes, symbol func2 at offset 0
    //   seg 3: 4 bytes, symbol func3 at offset 0
    segdef32(&mut out, 0x61, 8, 1, 2);   // seg 1: _TEXT/CODE
    segdef32(&mut out, 0x61, 12, 1, 2);  // seg 2: _TEXT/CODE
    segdef32(&mut out, 0x61, 4, 1, 2);   // seg 3: _TEXT/CODE

    // One _DATA/DATA segment (index 4):
    segdef32(&mut out, 0x61, 16, 3, 4);  // seg 4: _DATA/DATA

    // PUBDEF32 for each function
    pubdef32(&mut out, 0, 1, &[(b"_func1", 0)]);
    pubdef32(&mut out, 0, 2, &[(b"_func2", 0)]);
    pubdef32(&mut out, 0, 3, &[(b"_func3", 0)]);

    // LEDATA for each segment
    ledata(&mut out, 1, 0, &[0x55; 8]);
    ledata(&mut out, 2, 0, &[0x89; 12]);
    ledata(&mut out, 3, 0, &[0xC3; 4]);
    ledata(&mut out, 4, 0, &[0x00; 16]);

    // LINNUM32 for segments 1 and 2
    linnum32(&mut out, 0, 1, &[(10, 0x00), (11, 0x04)]);
    linnum32(&mut out, 0, 2, &[(20, 0x00), (21, 0x06)]);

    modend(&mut out);

    let mut file = object::File::parse(out.as_slice()).expect("parse");
    if let object::File::Omf(ref mut omf) = file {
        omf.merge_sections();
    }

    // After merging: 2 sections: merged _TEXT (24 bytes) + _DATA (16 bytes).
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 2, "expected 2 sections (merged _TEXT + _DATA), got {}", sections.len());

    let text_sec = &sections[0];
    assert_eq!(text_sec.name().unwrap_or(""), "_TEXT");
    assert_eq!(text_sec.size(), 24, "merged _TEXT should be 8+12+4=24 bytes");

    let data_sec = &sections[1];
    assert_eq!(data_sec.name().unwrap_or(""), "_DATA");
    assert_eq!(data_sec.size(), 16);

    // Verify symbol offsets are adjusted.
    let func1 = file.symbols().find(|s| s.name().unwrap_or("") == "_func1").unwrap();
    let func2 = file.symbols().find(|s| s.name().unwrap_or("") == "_func2").unwrap();
    let func3 = file.symbols().find(|s| s.name().unwrap_or("") == "_func3").unwrap();

    assert_eq!(func1.address(), 0, "_func1 should be at offset 0");
    assert_eq!(func2.address(), 8, "_func2 should be at offset 8 (after seg1's 8 bytes)");
    assert_eq!(func3.address(), 20, "_func3 should be at offset 20 (after seg1+seg2 = 20 bytes)");

    // All three symbols should reference the same section (merged _TEXT).
    assert_eq!(func1.section_index(), func2.section_index());
    assert_eq!(func2.section_index(), func3.section_index());

    // Verify line numbers are adjusted.
    if let object::File::Omf(ref omf) = file {
        let lines = omf.segment_line_numbers(0); // merged _TEXT is segment 0
        assert_eq!(lines.len(), 4, "expected 4 merged line entries");
        // seg 1 lines: (10, 0), (11, 4) — no offset adjustment
        assert_eq!(lines[0], (10, 0x00));
        assert_eq!(lines[1], (11, 0x04));
        // seg 2 lines: (20, 0+8=8), (21, 6+8=14) — adjusted by seg1 size
        assert_eq!(lines[2], (20, 0x08));
        assert_eq!(lines[3], (21, 0x0E));
    } else {
        panic!("expected OMF file");
    }
}

/// Segments with different names are NOT merged together.
#[test]
fn omf_merge_preserves_different_names() {
    use object::{Object, ObjectSection};

    let mut out = Vec::new();
    theadr(&mut out, b"diff.c");
    lnames(&mut out, &[b"_TEXT", b"CODE", b"_DATA", b"DATA", b"CONST"]);

    segdef32(&mut out, 0x61, 10, 1, 2); // seg 1: _TEXT/CODE
    segdef32(&mut out, 0x61, 20, 3, 4); // seg 2: _DATA/DATA
    segdef32(&mut out, 0x61, 30, 5, 4); // seg 3: CONST/DATA

    ledata(&mut out, 1, 0, &[0x90; 10]);
    ledata(&mut out, 2, 0, &[0x00; 20]);
    ledata(&mut out, 3, 0, &[0xFF; 30]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    let sections: Vec<_> = file.sections().collect();
    // All three segments have unique (name, class) → 3 sections, no merging.
    assert_eq!(sections.len(), 3, "expected 3 sections, got {}", sections.len());
    assert_eq!(sections[0].size(), 10);
    assert_eq!(sections[1].size(), 20);
    assert_eq!(sections[2].size(), 30);
}

/// Alignment padding between functions must be trimmed even when the CODE
/// segment is split across multiple LEDATA records (the normal Borland case).
///
/// Borland C++ emits `_TEXT` segments that often exceed a single LEDATA chunk,
/// so `get_single_chunk()` returns None and the first trim implementation
/// silently skipped these segments — leaving NOP-like padding bytes appended
/// to each function's size.  This test models that layout:
///
///   seg1 len=24 class=CODE
///     LEDATA chunk A: offset=0,  12 bytes → _f1 body (6 bytes) + 6 bytes pad
///                                           (lea eax,[eax+0] encoded 8D 80 ...)
///     LEDATA chunk B: offset=12, 12 bytes → _f2 body (6 bytes) + 6 bytes pad
///     PUBDEF: _f1@0, _f2@12
///
/// The 6-byte `lea eax, [eax+0x00000000]` encoding (`8D 80 00 00 00 00`) matches
/// the pattern shown in real Borland output.  After trimming, _f1 and _f2 must
/// each have size 6, not 12.
#[test]
fn omf_trim_padding_multi_ledata_code_segment() {
    use object::{Object, ObjectSymbol};

    let mut out = Vec::new();
    theadr(&mut out, b"multi_ledata.c");
    // LNAMES: idx1=_TEXT, idx2=CODE
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // SEGDEF32: one 24-byte _TEXT/CODE segment
    segdef32(&mut out, 0x61, 24, 1, 2);
    // PUBDEF: _f1 at 0, _f2 at 12
    pubdef32(&mut out, 0, 1, &[(b"_f1", 0), (b"_f2", 12)]);
    // Two LEDATA records covering the segment.
    // Each contains a 6-byte function body (push ebp; mov ebp,esp; pop ebp; ret)
    // followed by a 6-byte `lea eax, [eax+0x00000000]` padding (8D 80 00 00 00 00).
    ledata(
        &mut out,
        1,
        0,
        &[0x55, 0x89, 0xE5, 0x5D, 0xC3, 0xC3, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00],
    );
    ledata(
        &mut out,
        1,
        12,
        &[0x55, 0x89, 0xE5, 0x5D, 0xC3, 0xC3, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00],
    );
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    let f1 = file.symbols().find(|s| s.name().unwrap_or("") == "_f1").expect("_f1");
    let f2 = file.symbols().find(|s| s.name().unwrap_or("") == "_f2").expect("_f2");
    assert_eq!(
        f1.size(),
        6,
        "_f1: trailing `lea eax, [eax+0]` alignment padding must be trimmed even when \
         the segment has multiple LEDATA chunks"
    );
    assert_eq!(
        f2.size(),
        6,
        "_f2: trailing `lea eax, [eax+0]` alignment padding must be trimmed even when \
         the segment has multiple LEDATA chunks"
    );
}

/// Alignment padding must still be trimmed when a single symbol's byte range
/// spans multiple LEDATA chunks.  This is the case for Borland's large `_TEXT`
/// segments: the emitter flushes LEDATA every ~1 KiB, so any function crossing
/// that boundary is described by two consecutive chunks — the second of which
/// ends with the alignment padding.
#[test]
fn omf_trim_padding_symbol_spanning_ledata_chunks() {
    use object::{Object, ObjectSymbol};

    let mut out = Vec::new();
    theadr(&mut out, b"span.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    // SEGDEF32: one 16-byte _TEXT/CODE segment containing a single function.
    segdef32(&mut out, 0x61, 16, 1, 2);
    // Single PUBDEF: _big at 0.  compute_symbol_sizes() will initially set its
    // size to 16 (the whole segment).  Trimming must shrink it to 10.
    pubdef32(&mut out, 0, 1, &[(b"_big", 0)]);
    // First LEDATA: offset=0, 8 bytes (first half of the function body).
    ledata(&mut out, 1, 0, &[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0xC7, 0x45]);
    // Second LEDATA: offset=8, 8 bytes. First 2 bytes complete the function,
    // followed by a 6-byte `lea eax, [eax+0x00000000]` padding sled.
    ledata(&mut out, 1, 8, &[0xC9, 0xC3, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    let big = file.symbols().find(|s| s.name().unwrap_or("") == "_big").expect("_big");
    assert_eq!(
        big.size(),
        10,
        "_big: 6-byte trailing padding sled must be trimmed even when the \
         function's byte range spans two LEDATA chunks"
    );
}

/// A singleton segment is not affected by the merge pass.
#[test]
fn omf_no_merge_singletons() {
    use object::{Object, ObjectSection, ObjectSymbol};

    let mut out = Vec::new();
    theadr(&mut out, b"single.c");
    lnames(&mut out, &[b"_TEXT", b"CODE"]);
    segdef32(&mut out, 0x61, 16, 1, 2);
    pubdef32(&mut out, 0, 1, &[(b"_main", 0)]);
    ledata(&mut out, 1, 0, &[0x90; 16]);
    modend(&mut out);

    let file = object::File::parse(out.as_slice()).expect("parse");
    let sections: Vec<_> = file.sections().collect();
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].size(), 16);
    let sym = file.symbols().find(|s| s.name().unwrap_or("") == "_main").unwrap();
    assert_eq!(sym.address(), 0);
}

