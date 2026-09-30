#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 && data.len() <= 16416 {
        let _ = mikaki_webauthn::fuzz_android_extension(&data[32..], &data[..32]);
    }
});
