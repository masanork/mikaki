#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| sakimori_fuzz::assertion(data));
