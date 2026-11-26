# Quantum-Crypto Example

The public API tour in `lib/main.dart` demonstrates the algorithms, native keys,
and ten security-hardening checks introduced in 0.0.3. It uses the Dart facade,
not direct Rust bindings. Output goes through `dart:developer.log`; use Flutter's
Debug Console / DevTools logging to view it.

## Run

From this directory, with Flutter, Rust and the target platform toolchain installed:

```bash
flutter pub get
flutter run -d linux
```

Replace `linux` with your available device. From the repository root, the same
example can be exercised headlessly through its native integration test:

```bash
cargo build --release --manifest-path rust/Cargo.toml
flutter test test/example_security_tour_test.dart
```

## 0.0.3 checks

| Demonstration | Observed behavior required for PASS |
| :--- | :--- |
| Native Key Export Rejection | A key created with `exportable: false` rejects export |
| Native Key Use After Dispose Rejection | Signing with a disposed key is rejected |
| Native Shared Secret Handles | Encapsulation/decapsulation produce non-exportable native handles; derived AEAD keys interoperate |
| Hybrid KEM v2 Roundtrip | Version 2 encapsulation and decapsulation derive interoperable native AEAD keys |
| X25519 Invalid Key Rejection | Both a 32-byte all-zero key and an incorrectly sized key are rejected |
| Streaming v2 Tamper Detection | A modified tag is rejected after a valid multi-chunk round trip |
| Streaming v2 Truncation Detection | Removing the final byte is rejected |
| AEAD Incorrect AAD Rejection | Correct AAD opens the ciphertext; changed AAD is rejected |
| Secure Messaging v2 Context Tampering | Both message compositions open with the correct context and reject changed context |
| Legacy v1 Format Rejection | An actual empty v1 stream header and a message declaring version 1 are rejected |

Checks throw on unexpected acceptance or an error unrelated to the expected
rejection. The example stops on failure rather than reporting completion. All
native handles created by the hardening tour are disposed, including error paths.
No private keys or shared-secret bytes are printed.

## Reading the output

For the 17-byte `Critical Contract` document, the ML-DSA log reports:

```text
[DSA] Signed document.
[DSA] Attached signed message: 3326 bytes
```

That is the 3309-byte ML-DSA-65 signature plus the 17-byte message, using the
backend's attached-message convention. It is not a 3326-byte detached signature.
Hash-based signatures are reported separately as detached SPHINCS+ signatures.

ML-KEM labels use **NIST Security Category 1/3/5**, rather than claiming full
AES equivalence. Seed derivation logs describe derived key material or X25519
private-key bytes; they do not claim to generate an ML-KEM key pair. The one-run
benchmark is illustrative output, not a comparative performance result.

Successful logs establish only the demonstrated round trips and rejection cases.
They do not prove full standards conformance, comprehensive memory erasure, or
closure of every previous finding. The release remains Dev Preview; see the
[verification report](../doc/security-verification.md),
[threat model](../doc/threat-model.md), and [security policy](../SECURITY.md).
