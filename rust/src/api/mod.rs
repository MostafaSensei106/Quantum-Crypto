//! Flutter-Rust-Bridge API surface.
//!
//! Each module is a thin FFI boundary: owned types in, owned types out,
//! domain logic lives in `crate::core`. The bridge generates one Dart
//! module per file, so keep modules cohesive and parameter lists flat.

pub mod aead_api;
pub mod benchmark_api;
pub mod dsa_api;
pub mod hash_api;
pub mod hybrid_kem_api;
pub mod kdf_api;
pub mod kem_api;
pub mod key_serialization_api;
pub mod secure_messaging_api;
pub mod seed_keygen_api;
pub mod slh_dsa_api;
pub mod streaming_api;
