#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _=quantum_crypto::core::streaming::stream_decrypt(&[0;32],data);
    let _=quantum_crypto::core::security::decode_signed_payload(data);
    if let Ok(text)=std::str::from_utf8(data) {
        let _=quantum_crypto::api::key_serialization_api::hex_to_bytes(text.to_owned());
        let _=quantum_crypto::api::key_serialization_api::base64_to_bytes(text.to_owned());
    }
});
