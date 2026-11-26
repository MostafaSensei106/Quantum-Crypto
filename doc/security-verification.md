# Security verification  0.0.3

This is a local engineering verification record, not an independent audit.
The release remains Dev Preview. Do not interpret a checked engineering task
as an assurance that the library is production-ready.

## Local results (2026-11-26)

- Rust: 21 tests passed, including the vector suites and property tests.
- Flutter/FFI: 22 tests passed, including a benchmark smoke run (3 warmups,
  5 timed iterations). Smoke timings are not published performance measurements.
- Flutter analysis and Rust Clippy with warnings denied passed.
- Native release library and Linux example debug build succeeded.
- Parser fuzz smoke test completed 2,701,390 executions in 31 seconds without
  findings in the first unsandboxed run. The final unsandboxed run completed
  2,774,759 executions in 31 seconds successfully after the final parser changes.
  An intervening sandboxed run failed at LeakSanitizer shutdown because ptrace
  was restricted; it was rerun outside the sandbox without disabling sanitizers.
- Raw RustSec audit failed on the two upstream advisories listed below; local
  mitigations passed their regression/vector checks. Six maintenance warnings remain.
- macOS, Windows, Android and iOS CI/device runs were not executed locally.

## Reproduction

```sh
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
python3 tools/check_dependency_policy.py
cargo build --locked --release --manifest-path rust/Cargo.toml
flutter analyze --no-pub
flutter test --no-pub test/native_keys_test.dart test/hybrid_kem_test.dart test/hash_aead_kdf_test.dart test/ml_dsa_test.dart test/ml_kem_test.dart test/slh_dsa_test.dart
```

Linux Rust tests also call Python 3 and system OpenSSL libcrypto for independent
AES-GCM/ChaCha20-Poly1305 AEAD and STREAM-v2 decoding. This reference checks
empty and multi-segment data, header AAD and HKDF derivation. XChaCha has regression
and property tests but is not covered by that OpenSSL comparison.

The vector suites use four NIST AES-256-GCM cases, 72 selected NIST ACVP ML-KEM
cases, 57 selected Wycheproof ML-DSA verification cases and RFC 5869 case 1.
See [vector provenance](../rust/tests/vectors/README.md). They are subsets,
not complete NIST algorithm-validation or Wycheproof runs. Property tests exercise
random stream sizes/chunk sizes and malformed inputs (256 cases per property
by default). Protocol tampering and native lifecycle tests complement vectors.

Parser fuzzing:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cd rust
cargo +nightly fuzz run parsers -- -max_total_time=60 -max_len=8192
```

Fuzzes STREAM headers/framing, signed-payload lengths, hex and Base64. Seed valid
streams to extend authenticated-path coverage in sustained campaigns. Negative
cryptographic-path coverage also comes from explicit authenticated-stream tests.
A short run is smoke coverage, not evidence that every parser state was explored.

## Dependency findings and local mitigations

The local RustSec scan on 2026-11-26 reported **two upstream vulnerabilities**
and **six unmaintained-package warnings**, with no patched upstream versions:

- [RUSTSEC-2026-0586](https://rustsec.org/advisories/RUSTSEC-2026-0586.html):
  pqcrypto-mldsa 0.1.2 AVX2 verification non-conformance. The direct dependency
  disables default features and enables only `std`, selecting the portable
  implementation. `check_dependency_policy.py` rejects re-enabling SIMD features.
  Selected Wycheproof valid, norm and boundary cases pass. Cargo feature unification
  in a different Rust host could re-enable dependency features; check the actual
  final host feature graph as well.
- [RUSTSEC-2026-0585](https://rustsec.org/advisories/RUSTSEC-2026-0585.html):
  pqcrypto-mlkem 0.1.1 lacks FIPS 203 input checks. Shared validation now rejects
  public coefficients >=3329 and verifies `H(embedded_public_key)` with SHA3-256
  and constant-time comparison before decapsulation. Both plain ML-KEM and hybrid
  operations use these checks. Hybrid also binds supplied public keys to secrets.
  Selected NIST input-check vectors and generated-key mutation tests pass.
- Warnings remain for `paste`, `pqcrypto-internals`, `pqcrypto-mldsa`,
  `pqcrypto-mlkem`, `pqcrypto-sphincsplus`, and `pqcrypto-traits` being unmaintained.

These mitigations do not replace the upstream versions or solve their maintenance
status. Raw `cargo audit` **still fails** on the version advisories. CI deliberately
preserves that failure; no advisory is ignored and `continue-on-error` is not used.
Migration to maintained backends remains a production-release requirement.

```sh
cargo install cargo-audit --version 0.23.0 --locked
cargo audit --file rust/Cargo.lock
cargo audit --file rust/fuzz/Cargo.lock
```

## Supply chain and platform coverage

The repository commits native lockfiles, pins the FRB runtime/code generator
version and CI checkout action revision, and pins the Flutter SDK revision used
for platform checks. Dependabot monitors Cargo, pub and workflow dependencies.
CI has native/Flutter checks and example builds for Linux, macOS, Windows,
Android and iOS simulator; scheduled auditing and fuzzing are separate jobs.
No workflow was submitted or run remotely as part of these local changes.
Cross-platform jobs and physical-device behavior require confirmation on those
runners/devices. Hosted runner images, toolchains and transitive sources still
need ongoing review; pinning is not a supply-chain attestation.

## Production checklist

- [x] Replace streaming nonce reuse, authenticate headers/final/empty segments.
- [x] Reject non-contributory X25519 inputs; bind v2 cryptographic contexts.
- [x] Add native handles, export/usage restrictions and synchronized disposal.
- [x] Add checked size handling, AAD and controlled secret-buffer cleanup.
- [x] Add regression/property tests, selected vectors, independent AEAD checks,
  parser fuzz target, dependency scanning and five-platform CI definitions.
- [x] Correct examples/guarantees and document migration, threat model and disclosure.
- [ ] Independently review the hybrid combiner and both message compositions.
- [ ] Replace unmaintained backends and resolve raw dependency audit failures.
- [ ] Establish final FIPS 205 backend equivalence or migrate to a conforming backend.
- [ ] Run full relevant conformance/interoperability suites and sustained fuzzing.
- [ ] Confirm every platform CI job and physical Android/iOS behavior.
- [ ] Measure memory, FFI overhead and UI responsiveness with recorded hardware.
- [ ] Complete independent security audit and supply-chain release review.

Security guarantees and remaining memory limits are described in the
[threat model](threat-model.md). Identity, replay and session management remain
application responsibilities rather than pending promises of this primitive API.
