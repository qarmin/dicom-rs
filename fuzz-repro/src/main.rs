//! Standalone, stable-toolchain reproducer for crashes found by the
//! cargo-fuzz targets under `*/fuzz/fuzz_targets/`.
//!
//! Each subcommand mirrors one fuzz harness exactly (same calls, same
//! assertions), so a crash file produced by `cargo fuzz run <target>` can be
//! replayed here without needing nightly or the fuzz sanitizer build. This
//! also makes it a fast `--command` target for byte-level minimizers, since
//! it runs as a plain release binary instead of a sanitizer-instrumented one.
//!
//! Usage:
//!   dicom-fuzz-repro <target> <file>
//!
//! Targets: dataset-tokens, lazy-dataset-tokens, decode-image-file, open-file

use dicom_parser::dataset::lazy_read::LazyDataSetReader;
use dicom_parser::DataSetReader;
use dicom_pixeldata::PixelDecoder;
use dicom_transfer_syntax_registry::entries;
use std::error::Error;
use std::io::Cursor;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (target, path) = match (args.get(1), args.get(2)) {
        (Some(t), Some(p)) => (t.as_str(), p.as_str()),
        _ => {
            eprintln!("usage: {} <target> <file>", args[0]);
            eprintln!(
                "targets: dataset-tokens, lazy-dataset-tokens, decode-image-file, open-file"
            );
            return ExitCode::FAILURE;
        }
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("REPRO-BROKEN: failed to read input file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = match target {
        "dataset-tokens" => dataset_tokens(&data),
        "lazy-dataset-tokens" => lazy_dataset_tokens(&data),
        "decode-image-file" => decode_image_file(&data),
        "open-file" => open_file(&data),
        "open-file-diff" => open_file_diff(&data),
        "debug-open-file" => debug_open_file(&data),
        "charset-probe" => charset_probe(&data),
        other => {
            eprintln!("unknown target: {other}");
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => {
            println!("REPRO-OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("REPRO-BROKEN: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dataset_tokens(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let ts = entries::EXPLICIT_VR_LITTLE_ENDIAN.erased();
    if let Ok(reader) = DataSetReader::new_with_ts(data, &ts) {
        for token in reader {
            let _ = token;
        }
    }
    let ts = entries::IMPLICIT_VR_LITTLE_ENDIAN.erased();
    if let Ok(reader) = DataSetReader::new_with_ts(data, &ts) {
        for token in reader {
            let _ = token;
        }
    }
    Ok(())
}

fn lazy_dataset_tokens(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let ts = entries::EXPLICIT_VR_LITTLE_ENDIAN.erased();
    if let Ok(mut reader) = LazyDataSetReader::new_with_ts(Cursor::new(data), &ts) {
        while let Some(Ok(token)) = reader.advance() {
            let _ = token.into_owned();
        }
    }
    let ts = entries::IMPLICIT_VR_LITTLE_ENDIAN.erased();
    if let Ok(mut reader) = LazyDataSetReader::new_with_ts(Cursor::new(data), &ts) {
        while let Some(Ok(token)) = reader.advance() {
            let _ = token.into_owned();
        }
    }
    Ok(())
}

fn decode_image_file(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let obj = dicom_object::from_reader(data)?;
    let decoded = obj.decode_pixel_data()?;
    let pixels: Vec<u16> = decoded.to_vec()?;
    let size = decoded.rows() as u64
        * decoded.columns() as u64
        * decoded.samples_per_pixel() as u64
        * decoded.number_of_frames() as u64;
    assert_eq!(pixels.len() as u64, size);
    Ok(())
}

fn open_file(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut obj = dicom_object::OpenFileOptions::new()
        .read_preamble(dicom_object::file::ReadPreamble::Auto)
        .odd_length_strategy(dicom_object::file::OddLengthStrategy::Fail)
        .from_reader(data)?;

    for g in 0..=0x07FF {
        obj.remove_element(dicom_object::Tag(g, 0x0000));
    }

    let mut bytes = Vec::new();
    obj.write_all(&mut bytes)
        .expect("writing DICOM file should always be successful");

    let obj2 = dicom_object::from_reader(bytes.as_slice())
        .expect("serialized object should always deserialize");

    assert!(
        objects_equivalent(&obj, &obj2),
        "round-tripped object is not content-equivalent to the original"
    );

    Ok(())
}

/// Mirrors `objects_equivalent` in `object/fuzz/fuzz_targets/open_file.rs`:
/// content equality while ignoring header length fields, since
/// `Length::UNDEFINED` is intentionally non-reflexive.
fn objects_equivalent(
    obj1: &dicom_object::InMemDicomObject,
    obj2: &dicom_object::InMemDicomObject,
) -> bool {
    use dicom_core::value::Value;

    let tags1: std::collections::BTreeSet<dicom_core::Tag> =
        obj1.iter().map(|e| e.header().tag).collect();
    let tags2: std::collections::BTreeSet<dicom_core::Tag> =
        obj2.iter().map(|e| e.header().tag).collect();
    if tags1 != tags2 {
        return false;
    }

    for tag in tags1 {
        let e1 = obj1.element(tag).unwrap();
        let e2 = obj2.element(tag).unwrap();
        if e1.header().vr != e2.header().vr {
            return false;
        }
        match (e1.value(), e2.value()) {
            (Value::Primitive(p1), Value::Primitive(p2)) => {
                if !primitive_equivalent(p1, p2) {
                    return false;
                }
            }
            (Value::Sequence(s1), Value::Sequence(s2)) => {
                if s1.items().len() != s2.items().len() {
                    return false;
                }
                for (item1, item2) in s1.items().iter().zip(s2.items().iter()) {
                    if !objects_equivalent(item1, item2) {
                        return false;
                    }
                }
            }
            (Value::PixelSequence(seq1), Value::PixelSequence(seq2)) => {
                if seq1.fragments() != seq2.fragments() {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

/// Mirrors `primitive_equivalent` in `object/fuzz/fuzz_targets/open_file.rs`.
fn primitive_equivalent(
    p1: &dicom_core::value::PrimitiveValue,
    p2: &dicom_core::value::PrimitiveValue,
) -> bool {
    use dicom_core::value::PrimitiveValue::*;
    match (p1, p2) {
        (F32(a), F32(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.to_bits() == y.to_bits())
        }
        (F64(a), F64(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.to_bits() == y.to_bits())
        }
        _ => p1 == p2,
    }
}

fn open_file_diff(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut obj = dicom_object::OpenFileOptions::new()
        .read_preamble(dicom_object::file::ReadPreamble::Auto)
        .odd_length_strategy(dicom_object::file::OddLengthStrategy::Fail)
        .from_reader(data)?;

    for g in 0..=0x07FF {
        obj.remove_element(dicom_object::Tag(g, 0x0000));
    }

    let mut bytes = Vec::new();
    obj.write_all(&mut bytes)?;

    let obj2 = dicom_object::from_reader(bytes.as_slice())?;

    if obj.meta() != obj2.meta() {
        println!("META DIFFERS:");
        println!("  obj1: {:?}", obj.meta());
        println!("  obj2: {:?}", obj2.meta());
    } else {
        println!("meta: identical");
    }

    diff_obj(&obj, &obj2, "");

    Ok(())
}

fn primitive_variant_name(v: &dicom_core::value::PrimitiveValue) -> &'static str {
    use dicom_core::value::PrimitiveValue::*;
    match v {
        Empty => "Empty",
        Strs(_) => "Strs",
        Str(_) => "Str",
        Tags(_) => "Tags",
        U8(_) => "U8",
        I16(_) => "I16",
        U16(_) => "U16",
        I32(_) => "I32",
        U32(_) => "U32",
        I64(_) => "I64",
        U64(_) => "U64",
        F32(_) => "F32",
        F64(_) => "F64",
        Date(_) => "Date",
        DateTime(_) => "DateTime",
        Time(_) => "Time",
    }
}

fn print_value_diff(p1: &dicom_core::value::PrimitiveValue, p2: &dicom_core::value::PrimitiveValue) {
    use dicom_core::value::PrimitiveValue::*;
    macro_rules! diff_slice {
        ($a:expr, $b:expr, $eq:expr) => {{
            let a = $a;
            let b = $b;
            let eq = $eq;
            if a.len() != b.len() {
                println!("    length differs: {} vs {}", a.len(), b.len());
            }
            let n = a.len().min(b.len());
            let mut shown = 0;
            for i in 0..n {
                if !eq(a[i], b[i]) {
                    println!("    [{i}] {:?} vs {:?}", a[i], b[i]);
                    shown += 1;
                    if shown >= 10 {
                        println!("    ... (more differences omitted)");
                        break;
                    }
                }
            }
        }};
    }
    match (p1, p2) {
        (F32(a), F32(b)) => {
            let n = a.len().min(b.len());
            let mut shown = 0;
            for i in 0..n {
                if a[i] != b[i] {
                    println!(
                        "    [{i}] {:?} (bits={:#010x}, nan={}) vs {:?} (bits={:#010x}, nan={})",
                        a[i], a[i].to_bits(), a[i].is_nan(), b[i], b[i].to_bits(), b[i].is_nan()
                    );
                    shown += 1;
                    if shown >= 10 {
                        println!("    ... (more differences omitted)");
                        break;
                    }
                }
            }
        }
        (F64(a), F64(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x: f64, y: f64| x
            == y
            || (x.is_nan() && y.is_nan())),
        (U8(a), U8(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (U16(a), U16(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (I16(a), I16(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (U32(a), U32(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (I32(a), I32(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (U64(a), U64(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (I64(a), I64(b)) => diff_slice!(a.as_slice(), b.as_slice(), |x, y| x == y),
        (Strs(a), Strs(b)) => println!("    {:?} vs {:?}", a, b),
        (Str(a), Str(b)) => println!("    {:?} vs {:?}", a, b),
        _ => println!("    {:?} vs {:?}", p1, p2),
    }
}

fn diff_obj(
    obj1: &dicom_object::InMemDicomObject,
    obj2: &dicom_object::InMemDicomObject,
    path: &str,
) {
    let tags1: std::collections::BTreeSet<_> = obj1.iter().map(|e| e.header().tag).collect();
    let tags2: std::collections::BTreeSet<_> = obj2.iter().map(|e| e.header().tag).collect();
    for tag in tags1.symmetric_difference(&tags2) {
        println!(
            "{path}TAG {:?} present in obj1={} obj2={}",
            tag,
            tags1.contains(tag),
            tags2.contains(tag)
        );
    }
    for tag in tags1.intersection(&tags2) {
        let e1 = obj1.element(*tag).unwrap();
        let e2 = obj2.element(*tag).unwrap();
        let h1 = e1.header();
        let h2 = e2.header();
        if h1.vr != h2.vr {
            println!("{path}TAG {:?} VR DIFFERS: {:?} vs {:?}", tag, h1.vr, h2.vr);
        }
        if h1.len != h2.len {
            println!(
                "{path}TAG {:?} HEADER LEN DIFFERS: {:?} vs {:?}",
                tag, h1.len, h2.len
            );
        }
        use dicom_core::value::Value;
        match (e1.value(), e2.value()) {
            (Value::Primitive(p1), Value::Primitive(p2)) => {
                let n1 = primitive_variant_name(p1);
                let n2 = primitive_variant_name(p2);
                if n1 != n2 {
                    println!(
                        "{path}TAG {:?} PRIMITIVE VARIANT DIFFERS: {} vs {}  (obj1={:?} obj2={:?}) vr1={:?} vr2={:?} len1={:?} len2={:?}",
                        tag, n1, n2, p1, p2, h1.vr, h2.vr, h1.len, h2.len
                    );
                } else if p1 != p2 {
                    println!(
                        "{path}TAG {:?} PRIMITIVE VALUE DIFFERS (same variant {}):",
                        tag, n1
                    );
                    print_value_diff(p1, p2);
                }
            }
            (Value::Sequence(s1), Value::Sequence(s2)) => {
                if s1.items().len() != s2.items().len() {
                    println!(
                        "{path}TAG {:?} SEQUENCE ITEM COUNT DIFFERS: {} vs {}",
                        tag,
                        s1.items().len(),
                        s2.items().len()
                    );
                } else {
                    for (i, (item1, item2)) in s1.items().iter().zip(s2.items().iter()).enumerate() {
                        diff_obj(item1, item2, &format!("{path}{:?}[{}]/", tag, i));
                    }
                }
            }
            (Value::PixelSequence(_), Value::PixelSequence(_)) => {
                if e1.value() != e2.value() {
                    println!("{path}TAG {:?} PIXEL SEQUENCE DIFFERS", tag);
                }
            }
            _ => {
                println!("{path}TAG {:?} VALUE KIND DIFFERS (Primitive/Sequence/Pixel mismatch)", tag);
            }
        }
    }
}

fn dump_obj(obj: &dicom_object::InMemDicomObject, depth: usize) {
    use dicom_core::value::Value;
    let indent = "  ".repeat(depth);
    for e in obj.iter() {
        let h = e.header();
        eprintln!("{indent}{:?} vr={:?} len={:?}", h.tag, h.vr, h.len);
        if let Value::Sequence(seq) = e.value() {
            for (i, item) in seq.items().iter().enumerate() {
                eprintln!("{indent}  item[{i}]:");
                dump_obj(item, depth + 2);
            }
        }
    }
}

#[allow(dead_code)]
fn debug_open_file(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut obj = dicom_object::OpenFileOptions::new()
        .read_preamble(dicom_object::file::ReadPreamble::Auto)
        .odd_length_strategy(dicom_object::file::OddLengthStrategy::Fail)
        .from_reader(data)?;

    for g in 0..=0x07FF {
        obj.remove_element(dicom_object::Tag(g, 0x0000));
    }

    eprintln!("=== obj1 ===");
    dump_obj(&obj, 0);

    let mut bytes = Vec::new();
    obj.write_all(&mut bytes)?;
    std::fs::write("/tmp/rewritten.dcm", &bytes)?;
    eprintln!("wrote {} bytes to /tmp/rewritten.dcm", bytes.len());

    match dicom_object::from_reader(bytes.as_slice()) {
        Ok(_) => eprintln!("obj2 parsed OK"),
        Err(e) => eprintln!("obj2 parse FAILED: {e}"),
    }

    Ok(())
}

fn find_elem<'a>(
    obj: &'a dicom_object::InMemDicomObject,
    tag: dicom_core::Tag,
) -> Option<&'a dicom_object::mem::InMemElement> {
    use dicom_core::value::Value;
    for e in obj.iter() {
        if e.header().tag == tag {
            return Some(e);
        }
        if let Value::Sequence(seq) = e.value() {
            for item in seq.items() {
                if let Some(x) = find_elem(item, tag) {
                    return Some(x);
                }
            }
        }
    }
    None
}

#[allow(dead_code)]
fn charset_probe(data: &[u8]) -> Result<(), Box<dyn Error>> {
    use dicom_core::value::{PrimitiveValue, Value};
    use dicom_encoding::text::{SpecificCharacterSet, TextCodec};

    let obj = dicom_object::OpenFileOptions::new()
        .read_preamble(dicom_object::file::ReadPreamble::Auto)
        .odd_length_strategy(dicom_object::file::OddLengthStrategy::Fail)
        .from_reader(data)?;

    let e = find_elem(&obj, dicom_core::Tag(0x0008, 0x0100)).ok_or("tag not found")?;
    if let Value::Primitive(PrimitiveValue::Strs(s)) = e.value() {
        let text = &s[0];
        eprintln!("string char len = {}", text.chars().count());
        let codec = SpecificCharacterSet::from_code("ISO_IR 149").unwrap();
        match codec.encode(text) {
            Ok(bytes) => eprintln!("whole-string encode OK, {} bytes", bytes.len()),
            Err(e) => eprintln!("whole-string encode ERR: {:?}", e),
        }
        for (i, c) in text.char_indices() {
            let single = c.to_string();
            match codec.encode(&single) {
                Ok(b) => {
                    if b == [b'?'] && c != '?' {
                        eprintln!("char at byte {} = {:?} encodes to literal '?' alone", i, c);
                    }
                }
                Err(_) => eprintln!("char at byte {} = {:?} FAILS to encode alone", i, c),
            }
        }
    } else {
        eprintln!("unexpected value kind: {:?}", e.value());
    }

    Ok(())
}
