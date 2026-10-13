# 0.0.2
- **SLH-DSA (FIPS 205) stateless hash-based signatures** — `SLH-DSA-SHA2-128f`
  (Level 1), `-192f` (Level 3), `-256f` (Level 5) via a new `slh_dsa` API
  (`QuantumCrypto.slhDsa`). Detached signatures whose security rests solely
  on hash-function strength — no lattice assumptions. Only the fast-signing
  `f` parameter sets are exposed; see the Rust docs for the size/speed
  trade-off vs ML-DSA.

- **XChaCha20-Poly1305 AEAD cipher** — 24-byte random nonces, safe without a
  counter. Available in `aead`, `streaming`, and secure-messaging APIs as
  `AeadAlgorithm.xChaCha20Poly1305` (wire format: `24-byte nonce || ciphertext+tag`).

- **HKDF hash agility** — `hkdfDeriveWithHash` / `hkdfDeriveMultiWithHash`
  with explicit `HkdfHash.sha256 / sha384 / sha512` selection
  (`QuantumCrypto.kdf`, optional `hash` parameter, defaults to SHA-256).

- **One-shot hash API** — SHA-256/384/512 and SHA3-256/512 via a new `hash`
  service (`QuantumCrypto.hash`).

- **`benchmarkSlhDsaByName`** — per-variant SLH-DSA benchmarks; sign
  iterations are clamped to at most 5 (SLH-DSA signing is ~100× slower than
  ML-DSA by design). The Rust suite also covers XChaCha20-Poly1305 and the
  new hash algorithms.

- Refactored the Rust `api/` layer to clean-code patterns: each module
  documents its FFI contract, DTO conversions use `From` impls, shared
  validation/payload/nonce helpers are extracted (`kdf`, `secure_messaging`,
  `streaming`), and the benchmark suite uses typed algorithm tables instead
  of stringly-typed dispatch.

- Unknown algorithm names in the benchmark API now return descriptive errors
  instead of silently falling back to a default variant.

- `hex_to_bytes` accepts an optional `0x` prefix and reports the offending
  byte position; Base64 decoders tolerate surrounding whitespace.

- `bytes_to_hex` no longer allocates per byte (lookup-table encoder).

- Eliminated needless secret-key cloning at the KEM/DSA/hybrid FFI boundary:
  key bytes are now moved out of their zeroizing containers via
  `into_bytes()` / `into_parts()`, so no duplicate copies of secret material
  linger in memory.

## 0.0.1

- Initial release.
