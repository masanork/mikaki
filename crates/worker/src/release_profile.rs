//! Retained Wasm exports let offline release verification identify compile features.
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(not(any(feature = "messaging-beta", feature = "messaging-qualification")))]
#[wasm_bindgen]
pub fn mikaki_release_profile_default() {}

#[cfg(all(feature = "messaging-beta", not(feature = "messaging-qualification")))]
#[wasm_bindgen]
pub fn mikaki_release_profile_messaging_beta() {}

#[cfg(feature = "messaging-qualification")]
#[wasm_bindgen]
pub fn mikaki_release_profile_messaging_qualification() {}
