#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = mikaki_fuzz::assertion(data);
});
