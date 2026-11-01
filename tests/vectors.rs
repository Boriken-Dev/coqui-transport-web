//! The wire vectors the Rust and Dart suites both run, so the two implementations cannot drift.

use coqui_web::frame::{self, Decoder, FrameError};
use proptest::prelude::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/frames.json")).expect("the vectors are JSON")
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("the vectors hold hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn max(case: &Value) -> usize {
    usize::try_from(case["max"].as_u64().expect("a max")).expect("a small max")
}

#[test]
fn every_encode_vector_holds() {
    for case in vectors()["encode"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let got = frame::encode(text.as_bytes(), max(case));
        if case["error"].as_bool() == Some(true) {
            assert_eq!(got, Err(FrameError::Size), "{name}");
        } else {
            assert_eq!(hex(&got.unwrap()), case["hex"].as_str().unwrap(), "{name}");
        }
    }
}

#[test]
fn every_decode_vector_holds() {
    for case in vectors()["decode"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut decoder = Decoder::new(max(case));
        let mut got = Vec::new();
        let mut failed = false;
        for chunk in case["chunks"].as_array().unwrap() {
            decoder.push(&bytes(chunk.as_str().unwrap()));
            loop {
                match decoder.next_frame() {
                    Ok(Some(message)) => got.push(message),
                    Ok(None) => break,
                    Err(FrameError::Size) => {
                        failed = true;
                        break;
                    }
                    Err(other) => panic!("{name}: {other:?}"),
                }
            }
        }
        let expected: Vec<Vec<u8>> = match case.get("binary") {
            Some(binary) => binary
                .as_array()
                .unwrap()
                .iter()
                .map(|h| bytes(h.as_str().unwrap()))
                .collect(),
            None => case["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().as_bytes().to_vec())
                .collect(),
        };
        assert_eq!(got, expected, "{name}");
        assert_eq!(failed, case["error"].as_bool() == Some(true), "{name}");
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_return_frames_or_an_error_and_never_panic(
        chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16),
        maximum in 1_usize..128,
    ) {
        let mut decoder = Decoder::new(maximum);
        for chunk in &chunks {
            decoder.push(chunk);
            while let Ok(Some(message)) = decoder.next_frame() {
                prop_assert!(!message.is_empty() && message.len() <= maximum);
            }
        }
    }

    #[test]
    fn any_bounded_body_round_trips_through_any_split(
        body in proptest::collection::vec(any::<u8>(), 1..256),
        split in 0_usize..260,
    ) {
        let encoded = frame::encode(&body, 256).unwrap();
        let at = split.min(encoded.len());
        let mut decoder = Decoder::new(256);
        decoder.push(&encoded[..at]);
        let first = decoder.next_frame().unwrap();
        decoder.push(&encoded[at..]);
        let message = match first {
            Some(message) => message,
            None => decoder.next_frame().unwrap().unwrap(),
        };
        prop_assert_eq!(message, body);
    }
}
