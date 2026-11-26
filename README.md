<h1 align="center">Quantum-Crypto</h1>
<p align="center">
  <img src="https://socialify.git.ci/MostafaSensei106/Quantum-Crypto/image?custom_language=Rust&font=KoHo&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F138288138%3Fv%3D4&name=1&owner=1&pattern=Floating+Cogs&theme=Light" alt="Banner">
</p>

<p align="center">
  <strong>Post-quantum cryptography for Flutter, powered by Rust.</strong><br>
  Native FFI integration for <i>ML-KEM and ML-DSA</i>, <i>native key management</i>, and <i>authenticated encryption</i>.
</p>


<p align="center">
  <a href="https://pub.dev/packages/quantum_crypto"><img src="https://img.shields.io/pub/v/quantum_crypto.svg" alt="pub version"></a>
  <a href="https://pub.dev/packages/quantum_crypto/score"><img src="https://img.shields.io/pub/points/quantum_crypto.svg" alt="pub points"></a>
  <img src="https://img.shields.io/badge/status-dev%20preview-orange" alt="Status: development preview">
  <img src="https://img.shields.io/badge/platforms-android%20%7C%20ios%20%7C%20linux%20%7C%20macos%20%7C%20windows-blue" alt="Platforms">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License: GPL-3.0"></a>
</p>

**0.0.3 · Dev Preview.** This package has not received an independent security
audit and is not FIPS validated. Hybrid KEM and message protection are project
constructions requiring specialist review. See [security guarantees and limits](doc/threat-model.md),
[protocol formats](doc/protocols-v2.md), and the [migration guide](doc/migration-0.0.3.md).
The dependency scan still flags upstream versions and unmaintained packages;
local mitigations and remaining release blockers are documented in the
[verification report](doc/security-verification.md).

## Table of Contents

- [The Quantum Threat & The Solution](#quantum-threat)
- [Why Choose Quantum-Crypto?](#why-choose-quantum-crypto)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Getting Started (Installation)](#getting-started)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Performance Benchmarks](#performance-benchmarks)
- [Architecture](#architecture)
- [Testing](#testing)
- [Security & Migration](#security-and-migration)
- [Contributing](#contributing)
- [License](#license)


---

<a id="quantum-threat"></a>

## 🛡️ The Quantum Threat & The Solution

Classical public-key schemes such as RSA and elliptic-curve cryptography face a
threat from sufficiently capable quantum computers. ML-KEM and ML-DSA provide
post-quantum alternatives for key encapsulation and digital signatures.

Quantum-Crypto brings these operations into Flutter through a Rust core, alongside
authenticated symmetric encryption and native key management. Choosing an algorithm
is one part of building a secure application: key authentication, protocol design,
storage and operational limits still matter. No library can guarantee protection
against every future cryptanalytic development.

---

<a id="why-choose-quantum-crypto"></a>

## 🤔 Why Choose Quantum-Crypto?

Use a Dart facade for post-quantum operations while keeping cryptographic computation
in native implementations. Native key handles let application code generate a key,
sign or decrypt with it, read its public key, and dispose it without transporting
the generated private key into Dart.

**The FFI Advantage:**
The Rust dependencies provide the mathematical implementations and optimizations,
including NTT operations. `flutter_rust_bridge` connects them to the Dart API.
Buffer transfers, wrapper work and copies still involve Dart, and linking may be
static or dynamic depending on the platform. Performance and UI responsiveness
must be measured for the intended workload and device.

### 🔬 Technical Implementation Comparison

| Vector | Dart Cryptography | Pure Dart PQC | **Quantum-Crypto (Rust/FFI)** |
| :--- | :--- | :--- | :--- |
| **Mathematical Core** | Depends on the package and algorithms | Depends on the implementation | **Upstream Rust/C cryptographic implementations** |
| **Algorithm Standards** | Must be checked per implementation | Must be checked per implementation | **ML-KEM/ML-DSA backends; no FIPS validation; final SLH-DSA equivalence unverified** |
| **Secret Memory** | Depends on package and runtime behavior | Secrets may reside in Dart memory | **Optional native handles; byte APIs/import/export still involve Dart** |
| **Thread Isolation** | Synchronous work can occupy its isolate; isolates are available | Can use isolates for CPU work | **Async bridge calls for native operations; measure end-to-end responsiveness** |
| **Forward Secrecy** | A property of the protocol | A property of the protocol | **Not provided by the current static-recipient hybrid/message constructions** |

Implementation language alone does not establish standards compliance, security,
responsiveness or a speed advantage. Comparative performance requires equivalent
algorithms, parameters and execution conditions.

---

<a id="tech-stack"></a>

## 🛠 Tech Stack

- **Language**: Dart (public API), Rust (native core), C implementations through `pqcrypto`.
- **Framework**: Flutter / Dart.
- **FFI Bridge**: `flutter_rust_bridge` **2.13.0**, with matching generated bindings.
- **Key Management**: opaque native handles, fixed usage/export policies, synchronized disposal.
- **Algorithms Supported**:
  - Key Encapsulation (KEM): **ML-KEM-512, ML-KEM-768, ML-KEM-1024**.
  - Digital Signatures (DSA): **ML-DSA-44, ML-DSA-65, ML-DSA-87**.
  - Hash-Based Signatures: **SPHINCS+ SHA2-128f, SHA2-192f, SHA2-256f**, exposed through the historical `slhDsa` API names.
  - Experimental Hybrid KEM v2: **X25519 + ML-KEM**, with context-bound HKDF and non-contributory X25519 rejection.
  - AEAD Encryption: **AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305**, with optional AAD.
  - Hashing: **SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512**.
  - Data Processing: **STREAM-based in-memory chunked encryption v2**, **HKDF-SHA256/384/512**, **random master seeds and deterministic key-material derivation**.

> **Standards note:** using algorithms associated with FIPS 203/204 does not make
> this package FIPS validated. The `pqcrypto-sphincsplus` backend has not been
> established as equivalent to final FIPS 205 SLH-DSA; retained API names do not
> establish that equivalence.

Android, iOS, Linux, macOS and Windows are declared plugin targets. CI contains
build jobs for all five; workflow definitions do not establish that every job
has passed. Web deployment is not a supported security target for this release.

---

<a id="prerequisites"></a>

## 📋 Prerequisites

> [!TIP]
> You can use the Dart API without writing Rust. The Rust toolchain is required
> on the development machine to compile the native core for the target platform.

- Install Flutter and its platform toolchains; check your setup with `flutter doctor`.
- Install Rust and Cargo using [rustup](https://rustup.rs).
- **Windows**: install the C/C++ build tools required by Rust and Flutter Windows builds.
- **macOS / iOS**: install Xcode and the tooling required by Flutter for the target.
- **Android**: install the Android SDK/NDK required by the native build.
- **Linux**: install Flutter's desktop build dependencies, including a C/C++ compiler,
  CMake, Ninja, pkg-config and GTK development libraries.

> [!IMPORTANT]
> Flutter platform build scripts compile the Rust core during application builds.
> When running repository tests, build the native release library first so the
> bridge can load it. Linux interoperability tests also require Python 3 and
> system OpenSSL `libcrypto`.

---

<a id="getting-started"></a>

## 🚀 Getting Started (Installation)

### 1. Add the Dependency

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  quantum_crypto: ^0.0.3
```

```bash
flutter pub get
```

For reproducible Dev Preview deployments, pin `quantum_crypto: 0.0.3` instead of
using a range. Review the [migration guide](doc/migration-0.0.3.md) before upgrading
existing encrypted data: v1 streams and old message/hybrid formats are rejected.

### 2. Initialization

Initialize once before cryptographic operations. In your Flutter application's
`main()`, initialize the bridge before calling `runApp`:

```dart
import 'package:flutter/widgets.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await QuantumCrypto.init();
  // Call runApp with your application's root widget here.
}
```

### 3. Working on This Repository

```bash
git clone https://github.com/MostafaSensei106/Quantum-Crypto.git
cd Quantum-Crypto
flutter pub get
cargo build --release --manifest-path rust/Cargo.toml
```

No database, server credentials or application `.env` file is required for the
library examples. Package the matching native binary and Dart bindings together.

---

<a id="basic-usage"></a>

## 📖 Basic Usage

The snippets assume `QuantumCrypto.init()` has completed. Import
`dart:typed_data`, `dart:convert` when using UTF-8, and
`package:quantum_crypto/quantum_crypto.dart`. Statement-only snippets belong
inside an `async` function. Prefer native handles when private keys do not need
to leave Rust; the explicit byte-key APIs remain available.

### 1. Key Encapsulation Mechanism (ML-KEM)

Generate post-quantum keys and encapsulate a shared secret. This example uses
explicit byte-key APIs: the private key and shared secret reside in Dart.
For a native-only secret path, use `nativeKeys.generateKem`,
`nativeKeys.encapsulateKem`, and the recipient handle's `decapsulate`.

```dart
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> performKem() async {
  // 1. Generate Key Pair (e.g. ML-KEM-768 for NIST Security Level 3)
  final keyPair = await QuantumCrypto.kem.generateKeyPair(KemAlgorithm.mlKem768);

  // 2. Sender encapsulates a shared secret using the recipient's public key
  final encapsulation = await QuantumCrypto.kem.encapsulate(
    algorithm: KemAlgorithm.mlKem768,
    publicKey: keyPair.publicKey,
  );

  // Send encapsulation.ciphertext over the network...

  // 3. Recipient decapsulates to retrieve the exact same shared secret
  final sharedSecret = await QuantumCrypto.kem.decapsulate(
    algorithm: KemAlgorithm.mlKem768,
    ciphertext: encapsulation.ciphertext,
    secretKey: keyPair.secretKey,
  );
}
```

### 2. Digital Signatures (ML-DSA)

Sign without exposing a private key:

```dart
final key = await QuantumCrypto.nativeKeys.generateDsa(
  algorithm: DsaAlgorithm.mlDsa65,
  exportable: false,
);
try {
  final message = Uint8List.fromList([1, 2, 3]);
  final signature = await key.sign(message);
  final publicKey = await key.publicKey();
  final valid = await QuantumCrypto.dsa.verify(
    algorithm: DsaAlgorithm.mlDsa65,
    message: message,
    signature: signature,
    publicKey: publicKey,
  );
  print(valid);
} finally {
  await key.dispose();
}
```

The private key remains in Rust in this path. `dispose()` waits for active use,
clears the owned secret buffers and invalidates every native alias. Call it
explicitly; bridge finalization is only a backup. Handles live in this process
and are not hardware-backed keys or a persistent keystore.

`generateKem`, `generateHybrid`, `generateSlhDsa`, `generateAead`, and
`generateSeed` provide the other key types. `usages` can restrict operations;
incompatible operations are rejected in Rust. See [native key management](doc/native-keys.md).

### 3. Hash-Based Signatures (SPHINCS+ / SLH-DSA API Names)

The backend uses `pqcrypto-sphincsplus` SHA2 fast parameter sets. Final FIPS 205
SLH-DSA equivalence is unverified. Signatures are **detached**; the attached-message
convention used by the ML-DSA API is a backend/API choice, not a requirement of
ML-DSA itself. This byte-key example has the same Dart-memory limitations as the
KEM example. Native handles are available through `nativeKeys.generateSlhDsa`.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> signHashBased() async {
  final message = Uint8List.fromList(utf8.encode("Critical Contract"));

  // 1. Generate Key Pair (Level 1; use 192f/256f for Levels 3/5)
  final keyPair = await QuantumCrypto.slhDsa.generateKeyPair(
    SlhDsaAlgorithm.slhDsaSha2_128f,
  );

  // 2. Sign (returns detached signature bytes)
  final signature = await QuantumCrypto.slhDsa.sign(
    algorithm: SlhDsaAlgorithm.slhDsaSha2_128f,
    message: message,
    secretKey: keyPair.secretKey,
  );

  // 3. Verify
  final isValid = await QuantumCrypto.slhDsa.verify(
    algorithm: SlhDsaAlgorithm.slhDsaSha2_128f,
    message: message,
    signature: signature,
    publicKey: keyPair.publicKey,
  );
  print('SPHINCS+ signature valid: $isValid');
}
```

### 4. AEAD Symmetric Encryption

```dart
final key = await QuantumCrypto.nativeKeys.generateAead(
  algorithm: AeadAlgorithm.xChaCha20Poly1305,
);
try {
  final message = Uint8List.fromList([10, 20, 30]);
  final metadata = Uint8List.fromList([1]);
  final ciphertext = await key.encrypt(message, associatedData: metadata);
  final plaintext = await key.decrypt(ciphertext, associatedData: metadata);
  print(plaintext);
} finally {
  await key.dispose();
}
```

AAD is authenticated but unencrypted; both parties must supply identical bytes.
The existing `QuantumCrypto.aead` byte-key API also accepts `associatedData`.
For byte-key applications use `Random.secure()` or an operating-system CSPRNG,
not a zero-filled `Uint8List(32)`. Keep persistent keys in a platform keystore or
an encrypted key store whose wrapping key is protected separately. Handle export
and platform storage integration are explicit application responsibilities.

Random 96-bit nonces have a birthday collision risk. Adopt a conservative
application limit of at most 2^16 encryptions per key across all senders and
copies of that key, and rotate earlier for your threat model. This is a project
policy, not a universal AEAD security bound or an enforced counter. Prefer
XChaCha20-Poly1305 for random-nonce workloads; rotate keys for exposure and
lifecycle reasons even with its larger nonce space. See [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
and [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

### 5. Key Serialization

Easily convert keys between raw bytes, Hex, and Base64 formats.

```dart
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> serializeKeys() async {
  final keyPair = await QuantumCrypto.kem.generateKeyPair(KemAlgorithm.mlKem768);

  // To String
  final hexString = await QuantumCrypto.keys.bytesToHex(keyPair.publicKey);
  final base64String = await QuantumCrypto.keys.bytesToBase64(keyPair.publicKey);

  // From String
  final restoredKey = await QuantumCrypto.keys.hexToBytes(hexString);
}
```

### 6. Cryptographic Hashing

One-shot SHA-2 and SHA-3 digests for key commitment, content addressing, and
transcript hashing around the PQC primitives.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> hashData() async {
  final data = Uint8List.fromList(utf8.encode("hello"));

  final sha256 = await QuantumCrypto.hash.digest(HashAlgorithm.sha256, data);
  final sha3 = await QuantumCrypto.hash.digest(HashAlgorithm.sha3_512, data);
  print('SHA-256: ${sha256.length} bytes, SHA3-512: ${sha3.length} bytes');
}
```

### 7. Native Key Management

| Key type | Constructor | Secret operations |
| :--- | :--- | :--- |
| ML-DSA | `generateDsa` | `sign`, `signAndEncrypt`, `encryptAndSign` |
| SPHINCS+ | `generateSlhDsa` | `sign` |
| ML-KEM | `generateKem` | `decapsulate` into a shared-secret handle |
| Hybrid | `generateHybrid` | `decapsulate`, `decryptAndVerify`, `verifyAndDecrypt` |
| AEAD | `generateAead` | `encrypt`, `decrypt`, `streamEncrypt`, `streamDecrypt` |
| Master seed / shared secret | `generateSeed` / encapsulation result | `deriveAead` |

`exportable` defaults to `false` and cannot be enabled later. `exportSecret()` is
an explicit operation that succeeds only for an exportable key; exported bytes
then reside in Dart. `importKey` supports existing keys but cannot erase the
original Dart copies. A non-exportable parent cannot derive an exportable child.
The `usages` option restricts permitted operations in Rust.

Use `try/finally` and `await key.dispose()`. Disposal waits for active operations,
clears project-owned secret buffers, and invalidates native aliases. Derived
children have independent lifetimes. See [native key management](doc/native-keys.md)
for import, export and lifecycle details.

---

<a id="advanced-usage"></a>

## 🔬 Advanced Usage

### Defense-in-Depth with Hybrid KEM

Hybrid v2 combines ML-KEM and X25519 with a versioned, context-bound HKDF.
X25519 non-contributory shared secrets are rejected. All three parameter sets
are project constructions, not implementations of an established hybrid protocol.
A sufficiently capable quantum computer threatens X25519 as well; it is not a
fallback guarantee against quantum attacks on ML-KEM.

```dart
final hybridKeyPair = await QuantumCrypto.hybrid.generateKeyPair(
  HybridKemAlgorithm.mlKem768X25519,
);
final result = await QuantumCrypto.hybrid.encapsulate(
  algorithm: HybridKemAlgorithm.mlKem768X25519,
  mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
  x25519PublicKey: hybridKeyPair.x25519PublicKey,
);
final sharedSecret = await QuantumCrypto.hybrid.decapsulate(
  algorithm: HybridKemAlgorithm.mlKem768X25519,
  mlKemCiphertext: result.mlKemCiphertext,
  x25519EphemeralPk: result.x25519EphemeralPk,
  mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
  x25519PublicKey: hybridKeyPair.x25519PublicKey,
  mlKemSecretKey: hybridKeyPair.mlKemSecretKey,
  x25519SecretKey: hybridKeyPair.x25519SecretKey,
);
print(sharedSecret.length); // 32; byte-key API output resides in Dart.
```

For native shared secrets, use `nativeKeys.generateHybrid` and
`nativeKeys.encapsulateHybrid`, then derive an AEAD handle on each side with
the same algorithm, context and key index. The v2 ciphertext includes a version
byte; preserve the bytes exactly as returned. See [protocol formats](doc/protocols-v2.md).

### Sign-then-Encrypt Secure Messaging

The `messaging` APIs and matching native-key methods provide Sign-then-Encrypt
and Encrypt-then-Sign. Hybrid recipient keys are required. Version, composition,
algorithms, public keys, KEM outputs and application AAD are bound cryptographically.
Applications must authenticate public keys and implement identity, sessions,
sequence/message IDs and replay detection. These are message protection
primitives, not a complete chat protocol. Static recipient keys do not provide
forward secrecy after recipient-key compromise.

ML-DSA byte signatures currently use the upstream attached-message convention;
that is an API choice, not a requirement of ML-DSA. Hash-based signature APIs
return detached SPHINCS+ signatures. Messaging signs a domain-separated
SHA-256 transcript digest; it does not claim HashML-DSA conformance.

This native-key example keeps generated signing and recipient private keys in Rust:

```dart
final sender = await QuantumCrypto.nativeKeys.generateDsa(
  algorithm: DsaAlgorithm.mlDsa65,
);
try {
  final recipient = await QuantumCrypto.nativeKeys.generateHybrid(
    algorithm: HybridKemAlgorithm.mlKem768X25519,
  );
  try {
    final message = Uint8List.fromList(utf8.encode('Top Secret'));
    final context = Uint8List.fromList(utf8.encode('example/message/v2'));
    final package = await sender.signAndEncrypt(
      message: message,
      recipientAlgorithm: HybridKemAlgorithm.mlKem768X25519,
      recipientMlKemPublicKey: await recipient.publicKey(),
      recipientX25519PublicKey: await recipient.secondaryPublicKey(),
      associatedData: context,
    );
    final originalMessage = await recipient.decryptAndVerify(
      package: package,
      senderDsaPublicKey: await sender.publicKey(),
      associatedData: context,
    );
    print(utf8.decode(originalMessage)); // Top Secret
  } finally {
    await recipient.dispose();
  }
} finally {
  await sender.dispose();
}
```

For Encrypt-then-Sign, use `sender.encryptAndSign` and
`recipient.verifyAndDecrypt` with the corresponding package type. That mode
exposes the signature and supports verification before decryption. Hybrid
recipient keys are required in both modes; they are not optional.

The byte-key `QuantumCrypto.messaging` service also remains available. In v2,
creation requires `senderDsaPublicKey`, and opening requires the recipient's
ML-KEM and X25519 public keys in addition to secret keys. Both modes accept
`associatedData`, and package versions must be preserved.

### Streaming AEAD Encryption

```dart
final key = await QuantumCrypto.nativeKeys.generateAead(
  algorithm: AeadAlgorithm.xChaCha20Poly1305,
);
try {
  final data = Uint8List.fromList([1, 2, 3]);
  final encrypted = await key.streamEncrypt(data, chunkSize: 65536);
  final decrypted = await key.streamDecrypt(encrypted);
  print(decrypted);
} finally {
  await key.dispose();
}
```

Version 2 uses a fresh random salt, a derived per-stream key, authenticated
headers and STREAM sequence/final-segment authentication. Empty data includes an
authentication tag. Version 1 is rejected. These APIs take complete buffers;
they do not provide file streaming or constant-memory I/O.

Messages and stream plaintext are limited to 64 MiB, AAD to 1 MiB, and chunk
sizes to 1..1 MiB. Encoded streams must also fit the 66 MiB encoded-size limit;
small chunks can hit this limit sooner. FFI decoding itself may allocate before
Rust checks these bounds, so applications must also limit untrusted ingress.

The existing `QuantumCrypto.streaming.streamEncrypt` / `streamDecrypt` APIs
accept explicit byte keys and now use the same v2 format. The native example
above generates a process-local key for the round trip; persistent ciphertext
requires an application-managed key recovery/storage strategy.

### Key Derivation Function (HKDF)

Derive key material from a high-entropy shared secret. The byte API supports
SHA-256 (default), SHA-384 and SHA-512. The following function takes a shared
secret already obtained from a validated exchange; it does not generate one:

```dart
Future<Uint8List> deriveApplicationKey(Uint8List kemSharedSecret) async {
  return QuantumCrypto.kdf.derive(
    sharedSecret: kemSharedSecret,
    info: Uint8List.fromList(utf8.encode('example/aes256gcm/v2')),
    outputLength: 32,
    hash: HkdfHash.sha256,
  );
}
```

Use different contexts for different applications, protocols and algorithms.
`deriveMulti` can derive separate outputs with distinct `infoStrings`.
Native seed/shared-secret handles provide `deriveAead`, binding the chosen AEAD
algorithm, application context and key index without exporting the input secret.

### Deterministic Seed Generation

Master seeds are generated randomly; key material is derived deterministically.

```dart
final seed = await QuantumCrypto.nativeKeys.generateSeed();
try {
  final key = await seed.deriveAead(
    algorithm: AeadAlgorithm.xChaCha20Poly1305,
    context: Uint8List.fromList(utf8.encode('example/file-encryption/v2')),
    keyIndex: 0,
  );
  try {
    final ciphertext = await key.encrypt(
      Uint8List.fromList(utf8.encode('Derived-key example')),
    );
    print(ciphertext.length);
  } finally {
    await key.dispose();
  }
} finally {
  await seed.dispose();
}
```

Generate seeds from a CSPRNG. Seed length does not prove entropy, and HKDF is
not a password KDF. Compromise of a master seed exposes every key derivable
from it. The byte seed APIs derive key material, not deterministic ML-KEM or
ML-DSA key pairs. Native `deriveAead` requires an application context and binds
the chosen AEAD algorithm and key index. Use separate contexts for separate
protocols and applications.

Native handles avoid transporting generated private keys into Dart. Rust-owned
secret containers are cleared on disposal/drop where this project controls them.
No complete erasure guarantee is made for upstream C/PQ buffers, allocator
copies, stack/register spills, process dumps, or Dart buffers created through
legacy byte APIs, import or explicit export. Secret-bearing Dart key models use
identity equality and owned read-only byte snapshots.

---

<a id="performance-benchmarks"></a>

## ⚡ Performance Benchmarks

Cryptographic operations run in native dependencies; Dart-side measurements include
FFI and wrapper work. Algorithm names such as ML-KEM-1024 identify parameter sets,
not a claim that every operation is a "1024-dimensional" computation.

### 📊 Comprehensive Execution Benchmarks

> **Historical 0.0.2 results:** the table below retains the original measurements.
> CPU, RAM, operating system, architecture and build mode were not recorded.
> These are not measurements of 0.0.3 and do not establish superiority over Dart
> implementations. Hash-based and pipeline labels have been corrected to describe
> the backend/operation actually measured; numeric results are unchanged.

The in-repo Dart harness defaults to 100 warmup and 1000 timed iterations per
operation. To collect a new run after building the native library:

```bash
cargo build --release --manifest-path rust/Cargo.toml
flutter test test/benchmark_test.dart
```

| Algorithm / Operation | Step | Avg (μs) | Min (μs) | Max (μs) | Median (μs) | Ops/sec |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| **ML-KEM-512** | KeyGen | 96.8 | 78.0 | 1178.0 | 90.0 | 10326.0 |
| **ML-KEM-512** | Encapsulate | 86.2 | 72.0 | 362.0 | 82.0 | 11607.7 |
| **ML-KEM-512** | Decapsulate | 79.7 | 64.0 | 2068.0 | 73.0 | 12545.6 |
| **ML-KEM-512** | Roundtrip | 192.6 | 157.0 | 469.0 | 188.0 | 5191.4 |
| **ML-KEM-768** | KeyGen | 63.6 | 52.0 | 281.0 | 60.0 | 15729.9 |
| **ML-KEM-768** | Encapsulate | 63.4 | 51.0 | 332.0 | 61.0 | 15770.4 |
| **ML-KEM-768** | Decapsulate | 65.6 | 52.0 | 251.0 | 65.0 | 15235.5 |
| **ML-KEM-768** | Roundtrip | 182.0 | 146.0 | 580.0 | 180.0 | 5495.0 |
| **ML-KEM-1024** | KeyGen | 58.5 | 52.0 | 221.0 | 55.0 | 17099.3 |
| **ML-KEM-1024** | Encapsulate | 56.9 | 51.0 | 384.0 | 54.0 | 17572.2 |
| **ML-KEM-1024** | Decapsulate | 60.8 | 55.0 | 283.0 | 58.0 | 16455.8 |
| **ML-KEM-1024** | Roundtrip | 177.9 | 162.0 | 366.0 | 176.0 | 5619.6 |
| **ML-DSA-44** | KeyGen | 65.3 | 57.0 | 233.0 | 62.0 | 15319.3 |
| **ML-DSA-44** | Sign | 112.2 | 67.0 | 407.0 | 99.0 | 8915.2 |
| **ML-DSA-44** | Verify | 65.6 | 60.0 | 251.0 | 63.0 | 15252.3 |
| **ML-DSA-44** | Roundtrip | 244.7 | 190.0 | 621.0 | 230.0 | 4087.0 |
| **ML-DSA-65** | KeyGen | 79.8 | 74.0 | 323.0 | 76.0 | 12529.1 |
| **ML-DSA-65** | Sign | 153.3 | 85.0 | 676.0 | 134.0 | 6523.2 |
| **ML-DSA-65** | Verify | 81.5 | 74.0 | 464.0 | 77.0 | 12268.6 |
| **ML-DSA-65** | Roundtrip | 306.9 | 234.0 | 700.0 | 289.0 | 3258.4 |
| **ML-DSA-87** | KeyGen | 103.8 | 95.0 | 354.0 | 99.0 | 9632.4 |
| **ML-DSA-87** | Sign | 172.7 | 110.0 | 547.0 | 157.0 | 5790.8 |
| **ML-DSA-87** | Verify | 101.2 | 96.0 | 296.0 | 99.0 | 9879.5 |
| **ML-DSA-87** | Roundtrip | 377.6 | 305.0 | 988.0 | 357.0 | 2648.1 |
| **SPHINCS+-SHA2-128f** | KeyGen | 354.5 | 326.0 | 671.0 | 337.0 | 2821.1 |
| **SPHINCS+-SHA2-128f** | Sign | 7400.0 | 6665.0 | 10569.0 | 7366.0 | 135.1 |
| **SPHINCS+-SHA2-128f** | Verify | 684.3 | 638.0 | 951.0 | 654.0 | 1461.3 |
| **SPHINCS+-SHA2-128f** | Roundtrip | 8525.5 | 7912.0 | 10089.0 | 8492.0 | 117.3 |
| **SPHINCS+-SHA2-192f** | KeyGen | 517.9 | 449.0 | 748.0 | 486.0 | 1930.9 |
| **SPHINCS+-SHA2-192f** | Sign | 11482.8 | 10744.0 | 13374.0 | 11430.0 | 87.1 |
| **SPHINCS+-SHA2-192f** | Verify | 1029.8 | 899.0 | 1392.0 | 1046.0 | 971.1 |
| **SPHINCS+-SHA2-192f** | Roundtrip | 13203.0 | 12227.0 | 17817.0 | 13172.0 | 75.7 |
| **SPHINCS+-SHA2-256f** | KeyGen | 1393.6 | 1194.0 | 2272.0 | 1399.0 | 717.6 |
| **SPHINCS+-SHA2-256f** | Sign | 24150.2 | 23015.0 | 25731.0 | 24092.0 | 41.4 |
| **SPHINCS+-SHA2-256f** | Verify | 1165.9 | 972.0 | 6192.0 | 1177.0 | 857.7 |
| **SPHINCS+-SHA2-256f** | Roundtrip | 26899.2 | 25371.0 | 33231.0 | 26879.0 | 37.2 |
| **Hybrid ML-KEM-512** | KeyGen | 63.0 | 58.0 | 314.0 | 60.0 | 15881.1 |
| **Hybrid ML-KEM-512** | Encapsulate | 113.1 | 106.0 | 444.0 | 109.0 | 8844.8 |
| **Hybrid ML-KEM-512** | Decapsulate | 98.1 | 92.0 | 537.0 | 95.0 | 10189.1 |
| **Hybrid ML-KEM-512** | Roundtrip | 276.1 | 258.0 | 522.0 | 270.0 | 3621.7 |
| **Hybrid ML-KEM-768** | KeyGen | 78.3 | 61.0 | 460.0 | 75.0 | 12775.0 |
| **Hybrid ML-KEM-768** | Encapsulate | 127.0 | 113.0 | 393.0 | 121.0 | 7875.2 |
| **Hybrid ML-KEM-768** | Decapsulate | 110.4 | 98.0 | 366.0 | 104.0 | 9055.0 |
| **Hybrid ML-KEM-768** | Roundtrip | 309.7 | 276.0 | 763.0 | 305.0 | 3229.1 |
| **Hybrid ML-KEM-1024** | KeyGen | 78.6 | 69.0 | 352.0 | 75.0 | 12722.3 |
| **Hybrid ML-KEM-1024** | Encapsulate | 125.5 | 115.0 | 308.0 | 119.0 | 7968.2 |
| **Hybrid ML-KEM-1024** | Decapsulate | 111.1 | 103.0 | 295.0 | 106.0 | 9004.0 |
| **Hybrid ML-KEM-1024** | Roundtrip | 319.5 | 290.0 | 575.0 | 317.0 | 3130.1 |
| **AES-256-GCM (1 KB)** | Encrypt | 40.4 | 37.0 | 232.0 | 39.0 | 24735.3 |
| **AES-256-GCM (1 KB)** | Decrypt | 39.4 | 37.0 | 206.0 | 38.0 | 25405.2 |
| **AES-256-GCM (64 KB)** | Encrypt | 293.2 | 254.0 | 685.0 | 288.0 | 3411.2 |
| **AES-256-GCM (64 KB)** | Decrypt | 289.0 | 250.0 | 491.0 | 287.0 | 3460.2 |
| **AES-256-GCM (1 MB)** | Encrypt | 6348.3 | 5492.0 | 9861.0 | 6086.0 | 157.5 |
| **AES-256-GCM (1 MB)** | Decrypt | 6189.9 | 5384.0 | 9274.0 | 6016.0 | 161.6 |
| **ChaCha20-Poly1305 (1 KB)** | Encrypt | 42.7 | 36.0 | 1213.0 | 38.0 | 23392.4 |
| **ChaCha20-Poly1305 (1 KB)** | Decrypt | 40.0 | 36.0 | 288.0 | 38.0 | 25018.1 |
| **ChaCha20-Poly1305 (64 KB)** | Encrypt | 277.9 | 247.0 | 487.0 | 270.0 | 3598.4 |
| **ChaCha20-Poly1305 (64 KB)** | Decrypt | 273.4 | 244.0 | 448.0 | 276.0 | 3657.6 |
| **ChaCha20-Poly1305 (1 MB)** | Encrypt | 6195.7 | 5121.0 | 10439.0 | 5948.0 | 161.4 |
| **ChaCha20-Poly1305 (1 MB)** | Decrypt | 6388.2 | 5229.0 | 11221.0 | 6039.0 | 156.5 |
| **XChaCha20-Poly1305 (1 KB)** | Encrypt | 40.1 | 37.0 | 349.0 | 38.0 | 24929.0 |
| **XChaCha20-Poly1305 (1 KB)** | Decrypt | 38.5 | 36.0 | 271.0 | 37.0 | 25944.4 |
| **XChaCha20-Poly1305 (64 KB)** | Encrypt | 289.3 | 247.0 | 563.0 | 285.0 | 3457.2 |
| **XChaCha20-Poly1305 (64 KB)** | Decrypt | 283.8 | 242.0 | 667.0 | 280.0 | 3523.8 |
| **XChaCha20-Poly1305 (1 MB)** | Encrypt | 5678.1 | 4711.0 | 9779.0 | 5349.0 | 176.1 |
| **XChaCha20-Poly1305 (1 MB)** | Decrypt | 6241.1 | 5019.0 | 11728.0 | 5900.0 | 160.2 |
| **Streaming Encrypt (1MB, 64k)** | Process | 5322.8 | 4255.0 | 9965.0 | 4946.0 | 187.9 |
| **Streaming Decrypt (1MB, 64k)** | Process | 5553.4 | 4333.0 | 10676.0 | 5341.0 | 180.1 |
| **HKDF-SHA256** | Derive | 37.8 | 34.0 | 428.0 | 36.0 | 26440.3 |
| **HKDF-SHA512** | Derive | 37.1 | 34.0 | 223.0 | 36.0 | 26930.2 |
| **SHA-256 (1 KB)** | Digest | 38.8 | 35.0 | 310.0 | 38.0 | 25802.5 |
| **SHA3-512 (1 KB)** | Digest | 39.7 | 37.0 | 201.0 | 38.0 | 25166.7 |
| **Seed Generation** | Generate | 37.0 | 35.0 | 374.0 | 36.0 | 27058.5 |
| **HKDF Seed Bytes** | Derive | 40.3 | 37.0 | 316.0 | 39.0 | 24829.9 |
| **Encrypt-then-Sign Pipeline** | EncryptAndSign | 252.5 | 176.0 | 830.0 | 234.0 | 3959.7 |
| **Encrypt-then-Sign Pipeline** | VerifyAndDecr | 166.5 | 152.0 | 389.0 | 158.0 | 6006.4 |

### 🔬 Reproducing and Interpreting Results

Record hardware, OS, architecture, compiler versions, Rust/Flutter build modes,
commit, algorithm parameters, message sizes and iteration counts. Compare native
benchmark timings with end-to-end Dart timings using equivalent workloads.
Peak memory, allocations, frame drops, FFI overhead and physical Android/iOS
results require their own measurements. Parameter-set timings can vary across
platforms and runs; unexpected ordering needs investigation rather than a
blanket claim that one parameter set is faster.

A short API smoke run is available, but is not a publishable benchmark:

```bash
flutter test test/benchmark_test.dart --dart-define=BENCHMARK_WARMUP=3 --dart-define=BENCHMARK_ITERATIONS=5
```

See [benchmark methodology](doc/benchmarks.md) and the
[historical table provenance](doc/benchmarks-legacy.md).

---

<a id="architecture"></a>

## 🏛️ Architecture

```text
Flutter / Dart application
  → QuantumCrypto facade and public service interfaces
  → native key wrappers or explicit byte-key APIs
  → generated flutter_rust_bridge bindings
  → Rust API validation and opaque handle lifecycle
  → core engines / strategy factories
  → upstream PQC, AEAD, hash and KDF implementations
```

| Location | Responsibility |
| :--- | :--- |
| `lib/quantum_crypto.dart`, `lib/src/crypto.dart` | Public exports, initialization and facade |
| `lib/src/core/` | Algorithms, models and service interfaces |
| `lib/src/native/` | Public native-key wrappers |
| `lib/src/infrastructure/services/` | Byte-key service adapters |
| `lib/src/rust/`, `rust/src/frb_generated.rs` | Generated bridge code |
| `rust/src/api/`, `rust/src/core/`, `rust/src/factory/` | Native API, engines, validation and dispatch |
| `rust/tests/`, `rust/fuzz/`, `test/` | Vectors, regression/property tests, fuzzing and Dart integration |
| `example/`, `doc/`, `tools/` | Example application, detailed documentation and verification tools |

For bridge changes, regenerate with the matching code generator rather than
editing generated files by hand:

```bash
cargo install flutter_rust_bridge_codegen --version 2.13.0 --locked
flutter_rust_bridge_codegen generate
```

---

<a id="testing"></a>

## 🧪 Testing

### Running the Checks

Run these commands from the repository root:

```bash
flutter pub get
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
python3 tools/check_dependency_policy.py
cargo build --locked --release --manifest-path rust/Cargo.toml
flutter analyze --no-pub
flutter test --no-pub test/native_keys_test.dart test/hybrid_kem_test.dart test/hash_aead_kdf_test.dart test/ml_dsa_test.dart test/ml_kem_test.dart test/slh_dsa_test.dart
```

### Coverage and Verification

| Area | Checks |
| :--- | :--- |
| Streaming v2 | Empty input, header/ciphertext tampering, ordering, truncation, extra data and wrong keys |
| Hybrid / messaging v2 | Non-contributory X25519 rejection, key/context binding and version enforcement |
| Native keys | Export/usage restrictions, import, derivation, concurrent use and synchronized disposal |
| Reference vectors | Selected NIST AES-GCM/ML-KEM, RFC HKDF and Wycheproof ML-DSA cases |
| Interoperability | Independent OpenSSL AES-GCM/ChaCha20-Poly1305 and STREAM decoding on Linux |
| Parser robustness | Property tests and a libFuzzer target |

The recorded local verification includes 21 Rust tests, 22 Flutter tests including
a benchmark smoke run, and a Linux example build. Other platform/device runs
remain to be confirmed. These are engineering checks, not an independent audit
or full NIST conformance validation.

### Fuzzing and Dependency Auditing

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cd rust
cargo +nightly fuzz run parsers -- -max_total_time=60 -max_len=8192
```

Dependency scanning, from the repository root:

```bash
cargo install cargo-audit --version 0.23.0 --locked
cargo audit --file rust/Cargo.lock
cargo audit --file rust/fuzz/Cargo.lock
```

Raw dependency auditing still flags affected upstream versions and unmaintained
packages. Local mitigations disable the affected ML-DSA AVX2 path and validate
ML-KEM inputs; these do not replace the dependencies or resolve their maintenance
status. The [verification report](doc/security-verification.md) records findings,
commands, test-vector scope and production-release requirements.

---

<a id="security-and-migration"></a>

## 🔒 Security & Migration

| Topic | Current guarantee or responsibility |
| :--- | :--- |
| Development status | Dev Preview; no independent audit or FIPS validation |
| Native secrets | Generated private keys stay in Rust unless explicitly exportable and exported |
| Memory cleanup | Project-controlled secret buffers are cleared on close/drop; complete erasure across runtimes/dependencies is not guaranteed |
| Streaming | Authenticated v2 headers, sequence and final/empty segments; whole-buffer API |
| Hybrid / messaging | Context-bound project constructions requiring specialist review |
| Forward secrecy | Not provided after compromise of static recipient keys |
| Identity / replay / sessions | Application or higher-level protocol responsibility |
| Persistence | Native handles are process-local, not a hardware-backed or persistent keystore |
| Migration | v1 streams and old hybrid/message formats are rejected; no automatic fallback |

Keep persistent keys in a platform keystore or an encrypted store whose wrapping
key is protected separately. Plan recovery before discarding a process-local
handle used for persistent data. Never log private keys or master seeds.

Read the [threat model](doc/threat-model.md), [v2 protocol formats](doc/protocols-v2.md),
[migration guide](doc/migration-0.0.3.md) and [verification report](doc/security-verification.md).
Report vulnerabilities privately using the contact and process in [SECURITY.md](SECURITY.md).
Release changes are listed in [CHANGELOG.md](CHANGELOG.md).

---

<a id="contributing"></a>

## 🤝 Contributing

Contributions are welcome! Here’s how to get started:

1.  Fork the repository.
2.  Create a new branch: `git checkout -b feature/YourFeature`
3.  Commit your changes: `git commit -m "Add amazing feature"`
4.  Push to your branch: `git push origin feature/YourFeature`
5.  Open a pull request.

> 💡 Please read our **[Contributing Guidelines](CONTRIBUTING.md)** and open an issue first for major feature ideas or changes.

---

<a id="license"></a>

## ⚖️ License

This project is dual-licensed:

1. **Open Source License**: GPL-3.0
   - Free to use, modify, and distribute under GPL terms.
   - Any distributed modified version must also be GPL-3.0.

2. **Commercial License**:
   - Required for using the library in proprietary / closed-source products.
   - Only available from the copyright holder (Mostafa Mahmoud).
   - Contact: [mostafasensei106@gmail.com](mailto:mostafasensei106@gmail.com)

See the [LICENSE](LICENSE) file for full details.

<p align="center">
  Made with ❤️ by <a href="https://github.com/MostafaSensei106">MostafaSensei106</a>
</p>
