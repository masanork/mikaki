//! Isolated deterministic interoperability probe. Seeds are public fixtures,
//! never production keys. This crate is deliberately outside the product workspace.

use ml_dsa::{Keypair, MlDsa65, SignatureEncoding, Signer, SigningKey, Verifier};
use ml_kem::{DecapsulationKey, MlKem768, Seed, kem::Decapsulate};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn self_test() -> bool {
    kem_round_trip() && signature_round_trip()
}

fn kem_round_trip() -> bool {
    let decapsulation = DecapsulationKey::<MlKem768>::from_seed(Seed::from([0x41; 64]));
    let encapsulation = decapsulation.encapsulation_key();
    let (ciphertext, sent) =
        encapsulation.encapsulate_deterministic(&ml_kem::B32::from([0x42; 32]));
    let received = decapsulation.decapsulate(&ciphertext);
    if sent != received {
        return false;
    }
    let mut changed = ciphertext;
    changed[0] ^= 1;
    decapsulation.decapsulate(&changed) != sent
}

fn signature_round_trip() -> bool {
    let signing = SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from([0x43; 32]));
    let verifying = signing.verifying_key();
    let message = b"mikaki-pqc-probe-v1";
    let signature = signing.sign(message);
    verifying.verify(message, &signature).is_ok()
        && verifying
            .verify(b"mikaki-pqc-probe-v2", &signature)
            .is_err()
        && signature.to_bytes().len() == 3309
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::KeyExport;

    #[test]
    fn ml_kem_768_and_ml_dsa_65_round_trip_and_reject_changes() {
        assert!(self_test());
        let decapsulation = DecapsulationKey::<MlKem768>::from_seed(Seed::from([0x41; 64]));
        let public_bytes = decapsulation.encapsulation_key().to_bytes();
        assert_eq!(public_bytes.len(), 1184);
        let (ciphertext, _) = decapsulation
            .encapsulation_key()
            .encapsulate_deterministic(&ml_kem::B32::from([0x42; 32]));
        assert_eq!(ciphertext.len(), 1088);
        let signing = SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from([0x43; 32]));
        assert_eq!(signing.verifying_key().encode().len(), 1952);
    }
}
