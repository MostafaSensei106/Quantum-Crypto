## 0.0.3

Security hardening Dev Preview. Not independently audited or FIPS validated.

- **Breaking:** Streaming v2 replaces v1 with RustCrypto STREAM-BE32,
  per-stream HKDF keys, authenticated headers and authenticated final/empty
  segments. Rejects v1, truncation, reordering and trailing data.

- **Breaking:** Hybrid KEM v2 rejects non-contributory X25519 exchanges and
  binds algorithm, recipient public keys and ciphertexts in the KDF. Requires
  explicit recipient public keys for decapsulation; prefixes ciphertext with v2.

- **Breaking:** Message protection v2 binds composition, version, algorithms,
  sender/recipient public keys, KEM outputs and application AAD. Signatures
  authenticate a domain-separated transcript digest. Old packages are rejected.

- **Native key handles:** generate, import, sign, decapsulate, derive, encrypt,
  decrypt, protect messages and dispose without exporting generated secrets.
  Export is opt-in at creation/import; usage and algorithm policies are enforced
  in Rust. Disposal synchronizes with operations and invalidates native aliases.

- Disabled the upstream ML-DSA AVX2 verifier affected by RUSTSEC-2026-0586;
  added ML-KEM public coefficient and secret-key hash checks for
  RUSTSEC-2026-0585. Raw dependency audit still flags the upstream versions;
  unmaintained-backend warnings remain documented and unsuppressed.

- Added optional AAD to Dart AEAD APIs, checked sizes and operation limits,
  zeroizing temporary buffers and recoverable Unicode hex decoding errors.

- Secret-bearing Dart key models now use identity equality and owned read-only
  bytes. Reduced redundant FFI-result copies. Rust release panics use unwind.

- Added security regression/property tests, NIST AES-GCM and RFC HKDF vectors,
  independent OpenSSL checks, parser fuzzing, dependency scanning and CI jobs
  for five plugin platforms. Definitions do not imply all platform jobs passed.

- Corrected README guarantees and examples; added migration, protocol, native
  key, threat model, disclosure and benchmark methodology documentation.

- Hybrid/message constructions still require specialist review; replay, identity
  and sessions remain application responsibilities. Upstream SPHINCS+ is not
  claimed to be verified final FIPS 205 SLH-DSA. Native handles are process-local,
  not hardware-backed or persistent. See the verification report for coverage.

## 0.0.2
- **SPHINCS+ stateless hash-based signatures (exposed under SLH-DSA API names)**  `SLH-DSA-SHA2-128f`
  (Level 1), `-192f` (Level 3), `-256f` (Level 5) via a new `slh_dsa` API
  (`QuantumCrypto.slhDsa`). Detached signatures whose security rests solely
  on hash-function strength  no lattice assumptions. Only the fast-signing
  `f` parameter sets are exposed; see the Rust docs for the size/speed
  trade-off vs ML-DSA.

- **XChaCha20-Poly1305 AEAD cipher**  24-byte random nonces, with a larger random-nonce space. Available in `aead`, `streaming`, and secure-messaging APIs as
  `AeadAlgorithm.xChaCha20Poly1305` (wire format: `24-byte nonce || ciphertext+tag`).

- **HKDF hash agility**  `hkdfDeriveWithHash` / `hkdfDeriveMultiWithHash`
  with explicit `HkdfHash.sha256 / sha384 / sha512` selection
  (`QuantumCrypto.kdf`, optional `hash` parameter, defaults to SHA-256).

- **One-shot hash API**  SHA-256/384/512 and SHA3-256/512 via a new `hash`
  service (`QuantumCrypto.hash`).

- **`benchmarkSlhDsaByName`**  per-variant SLH-DSA benchmarks; sign
  iterations are clamped to at most 5 (hash-based signing can be slower than
  ML-DSA depending on the variant and platform). The Rust suite also covers XChaCha20-Poly1305 and the
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
  `into_bytes()` / `into_parts()`, reducing copies at that boundary. This does not guarantee erasure of Dart or upstream buffers.

## 0.0.1

- Initial release.
