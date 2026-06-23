#![no_main]
use dicom_core::value::Value;
use dicom_core::Tag;
use dicom_object::InMemDicomObject;
use libfuzzer_sys::{fuzz_target, Corpus};
use std::error::Error;

fuzz_target!(|data: &[u8]| -> Corpus {
    match fuzz(data) {
        Ok(_) => Corpus::Keep,
        Err(_) => Corpus::Reject,
    }
});

fn fuzz(data: &[u8]) -> Result<(), Box<dyn Error>> {
    // deserialize random bytes
    let mut obj = dicom_object::OpenFileOptions::new()
        .read_preamble(dicom_object::file::ReadPreamble::Auto)
        .odd_length_strategy(dicom_object::file::OddLengthStrategy::Fail)
        .from_reader(data)?;

    // remove group length elements
    for g in 0..=0x07FF {
        obj.remove_element(dicom_object::Tag(g, 0x0000));
    }
    // serialize object back to bytes
    let mut bytes = Vec::new();
    obj.write_all(&mut bytes)
        .expect("writing DICOM file should always be successful");

    // deserialize back to object
    let obj2 = dicom_object::from_reader(bytes.as_slice())
        .expect("serialized object should always deserialize");

    // assert equivalence
    //
    // `assert_eq!` is intentionally not used here: `Length::UNDEFINED` is
    // documented as never equal to itself (like NaN, see `Length`'s docs),
    // and `DataElement`'s derived `PartialEq` compares the header's length
    // along with the value. Two elements both legitimately encoded with an
    // undefined length (e.g. delimited sequences/items, very common in
    // practice) would then always compare as unequal even when their
    // content is identical, so `assert_eq!(obj, obj2)` is not a valid
    // round-trip check for such files.
    assert!(
        objects_equivalent(&obj, &obj2),
        "round-tripped object is not content-equivalent to the original"
    );

    Ok(())
}

/// Compares two DICOM objects for content equivalence, ignoring header
/// length fields (which may legitimately differ between a defined and an
/// undefined encoding of the same content, and which are otherwise
/// redundant with the value itself).
fn objects_equivalent(obj1: &InMemDicomObject, obj2: &InMemDicomObject) -> bool {
    let tags1: std::collections::BTreeSet<Tag> =
        obj1.iter().map(|e| e.header().tag).collect();
    let tags2: std::collections::BTreeSet<Tag> =
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

/// Compares two primitive values for content equivalence.
///
/// Falls back to bit-exact comparison for float arrays: IEEE 754 NaN is
/// never equal to itself under `==`, so the derived `PartialEq` on
/// `PrimitiveValue` would report a round-trip mismatch for any element
/// that legitimately holds a NaN (e.g. an `FL`/`FD`/`OF`/`OD` element),
/// even when the encoded bits are byte-for-byte identical before and
/// after the round trip.
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
