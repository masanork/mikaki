#![no_main]
use libfuzzer_sys::fuzz_target;

// An inert detector control, never one of the four product assessment targets.
fuzz_target!(|data: &[u8]| {
    assert_ne!(
        data, b"mikaki fuzz harness canary v1",
        "mikaki fuzz harness canary v1"
    );
});
