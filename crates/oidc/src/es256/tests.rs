use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};

struct Fixture {
    public: Vec<u8>,
    compressed: Vec<u8>,
    high_s: Vec<u8>,
    low_s: Vec<u8>,
    message: Vec<u8>,
}

fn fixture() -> Fixture {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/es256-rfc6979.json")).unwrap();
    Fixture {
        public: B64.decode(data["public_key"].as_str().unwrap()).unwrap(),
        compressed: B64
            .decode(data["compressed_public_key"].as_str().unwrap())
            .unwrap(),
        high_s: B64.decode(data["signature"].as_str().unwrap()).unwrap(),
        low_s: B64
            .decode(data["alternate_signature"].as_str().unwrap())
            .unwrap(),
        message: data["message"].as_str().unwrap().as_bytes().to_vec(),
    }
}

#[test]
fn rfc6979_both_sec1_encodings_and_both_s_values_preserve_acceptance() {
    let Fixture {
        public: full,
        compressed,
        high_s,
        low_s,
        message,
    } = fixture();
    for key in [&full, &compressed] {
        for signature in [&high_s, &low_s] {
            assert!(
                Es256Verification::new(key, signature, &message)
                    .unwrap()
                    .verify_reference()
                    .is_ok()
            );
            assert!(
                Es256Verification::new(key, signature, b"tampered")
                    .unwrap()
                    .verify_reference()
                    .is_err()
            );
        }
    }
}

#[test]
fn strict_p1363_ranges_and_point_shapes_match_the_reference_parser() {
    let Fixture {
        public: full,
        high_s: signature,
        message,
        ..
    } = fixture();
    for bytes in [
        Vec::new(),
        vec![0; 63],
        vec![0; 64],
        vec![1; 65],
        vec![0x30; 70],
    ] {
        assert!(Es256Verification::new(&full, &bytes, &message).is_err());
    }
    let order = B64
        .decode("_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE")
        .unwrap();
    for scalar in [vec![0; 32], order, vec![0xff; 32]] {
        for half in [0, 32] {
            let mut invalid = signature.clone();
            invalid[half..half + 32].copy_from_slice(&scalar);
            assert!(Signature::from_slice(&invalid).is_err());
            assert!(Es256Verification::new(&full, &invalid, &message).is_err());
        }
    }
    for key in [vec![], vec![4; 33], vec![2; 65], vec![0; 65], vec![4; 64]] {
        assert!(Es256Verification::new(&key, &signature, &message).is_err());
    }
    let mut off_curve = vec![0; 65];
    off_curve[0] = 4;
    assert!(
        Es256Verification::new(&off_curve, &signature, &message)
            .unwrap()
            .verify_reference()
            .is_err()
    );
}

#[test]
fn pending_verification_owns_a_snapshot_of_all_inputs() {
    let Fixture {
        public: mut key,
        high_s: mut signature,
        mut message,
        ..
    } = fixture();
    let pending = Es256Verification::new(&key, &signature, &message).unwrap();
    key.fill(0);
    signature.fill(0);
    message.fill(0);
    assert!(pending.verify_reference().is_ok());
}
