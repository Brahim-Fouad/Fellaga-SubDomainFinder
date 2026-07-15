#![no_main]

use fellaga_core::util::{extract_observed_names, normalize_hostname};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = normalize_hostname(text);
        let _ = extract_observed_names(text, "example.com");
    }
});
