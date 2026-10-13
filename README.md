<h1 align="center">Quantum-Crypto</h1>
<p align="center">
  <img src="https://socialify.git.ci/MostafaSensei106/Quantum-Crypto/image?custom_language=Rust&font=KoHo&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F138288138%3Fv%3D4&name=1&owner=1&pattern=Floating+Cogs&theme=Light" alt="Banner">
</p>

<p align="center">
  <strong>An advanced, Post-Quantum Cryptography suite for Flutter, powered by Rust.</strong><br>
  Future-proof your Flutter applications with implementations of <i>NIST-standardized algorithms</i> (ML-KEM, ML-DSA), <i>hybrid key exchanges</i>, and <i>secure messaging protocols</i>.
</p>


<p align="center">
  <a href="https://pub.dev/packages/quantum_crypto"><img src="https://img.shields.io/pub/v/quantum_crypto.svg" alt="pub version"></a>
  <a href="https://pub.dev/packages/quantum_crypto/score"><img src="https://img.shields.io/pub/points/quantum_crypto.svg" alt="pub points"></a>
  <img src="https://img.shields.io/badge/status-dev%20preview-orange" alt="Status: development preview">
  <img src="https://img.shields.io/badge/platforms-android%20%7C%20ios%20%7C%20linux%20%7C%20macos%20%7C%20windows-blue" alt="Platforms">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License: GPL-3.0"></a>
</p>


## Table of Contents

- [Why Choose Quantum-Crypto?](#-why-choose-quantum-crypto)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Getting Started (Installation)](#-getting-started-installation)
- [Basic Usage](#-basic-usage)
- [Advanced Usage](#-advanced-usage)
- [Performance Benchmarks](#-performance-benchmarks)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🛡️ The Quantum Threat & The Solution

> "With the NIST standardization of ML-KEM and ML-DSA (FIPS 203 & FIPS 204), transitioning to Post-Quantum Cryptography is no longer theoretical; it is an immediate engineering requirement."

Classical public-key infrastructure (RSA, ECC, Curve25519) relies on integer factorization and discrete logarithms mathematical problems that Shor's algorithm can trivially solve on a sufficiently stable quantum computer. 

While transitioning to lattice based cryptography (such as Kyber/ML-KEM and Dilithium/ML-DSA) solves the quantum threat vector, it introduces significant computational overhead. The polynomial matrices used in these algorithms require heavily optimized mathematics (e.g., the Number Theoretic Transform or NTT).

**The FFI Advantage:**
Implementing NTT and matrix arithmetic in pure Dart leads to heavy heap allocations, garbage collection thrashing, and UI thread blocking. `Quantum-Crypto` bypasses the Dart runtime entirely for cryptographic operations. By statically linking a compiled Rust core and passing memory pointers across the Flutter FFI boundary (Zero-Copy), the library achieves raw native execution speeds on both ARM and x86 architectures, minimizing UI thread blocking.

### 🔬 Technical Implementation Comparison

| Vector | Legacy Dart Crypto | Pure Dart PQC | **Quantum-Crypto (Rust/FFI)** |
| :--- | :--- | :--- | :--- |
| **Mathematical Core** | Prime Factorization / ECC | Lattice-Based | **Lattice-Based (NTT Optimized)** |
| **Algorithm Standards** | Legacy | Drafts / Unverified | **✅ Implements FIPS 203 / 204 / 205** |
| **Memory Allocation** | Dart Heap (Garbage Collected) | Dart Heap (Heavy Thrashing) | **🚀 Native Rust Allocator** |
| **Thread Isolation** | Blocks Isolate if sync | Blocks Isolate | **⚡ OS-Level Background Threads** |
| **Forward Secrecy** | Classical (ECDHE) | None | **🛡️ Hybrid (X25519 + ML-KEM)** |

---

## 🛠 Tech Stack

- **Language**: Dart (Frontend), Rust (Core Cryptography)
- **Framework**: Flutter / Dart
- **FFI Bridge**: `flutter_rust_bridge` (v2)
- **Algorithms Supported**:
  - Key Encapsulation (KEM): **ML-KEM-512, ML-KEM-768, ML-KEM-1024**
  - Digital Signatures (DSA): **ML-DSA-44, ML-DSA-65, ML-DSA-87**
  - Hash-Based Signatures: **SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-256f**
  - Hybrid KEM: **X25519 + ML-KEM**
  - AEAD Encryption: **AES-256-GCM, ChaCha20Poly1305, XChaCha20Poly1305**
  - Hashing: **SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512**
  - Data Processing: **Streaming Encryption, HKDF (SHA-256/384/512), Deterministic Seed Generation**

---

## 📋 Prerequisites

> [!TIP]
> **Don't worry about the "Rust Core"!**
> Adding **Quantum-Crypto** to your project is designed to be as simple as adding any other Flutter package. You don't need to be a Rust expert or manage complex builds manually.

Since this library uses a high-speed bridge to connect Flutter and Rust, you need the Rust compiler installed on your development machine to build the native binaries for your target platform.

- **Windows**: Download and run [rustup-init.exe](https://rustup.rs).
- **macOS / Linux**: Run the following command in your terminal:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

> [!IMPORTANT]
> Once Rust is installed, the build system will automatically detect your Flutter target and compile the Rust core into a high performance native shared library. You only need to set this up once!

---

## 🚀 Getting Started (Installation)

### 1. Add the Dependency

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  quantum_crypto: ^0.0.1
```

### 2. Initialization

You must initialize the native Rust library in your `main()` function before performing any cryptographic operations. This boots up the FFI bridge and allocates memory.

```dart
import 'package:flutter/material.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Load the native Rust binary into memory
  await QuantumCrypto.init();
  
  runApp(const MyApp());
}
```

---

## 📖 Basic Usage

### 1. Key Encapsulation Mechanism (ML-KEM)

Generate post-quantum keys and securely encapsulate a shared secret.

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

Sign and verify data with quantum resistant signatures.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> signDocument() async {
  final message = Uint8List.fromList(utf8.encode("Critical Contract"));
  
  // 1. Generate Key Pair
  final keyPair = await QuantumCrypto.dsa.generateKeyPair(DsaAlgorithm.mlDsa65);

  // 2. Sign the message
  final signature = await QuantumCrypto.dsa.sign(
    algorithm: DsaAlgorithm.mlDsa65,
    message: message,
    secretKey: keyPair.secretKey,
  );

  // 3. Verify the signature
  final isValid = await QuantumCrypto.dsa.verify(
    algorithm: DsaAlgorithm.mlDsa65,
    message: message,
    signature: signature,
    publicKey: keyPair.publicKey,
  );
  print('Signature valid: $isValid');
}
```

### 3. Hash-Based Signatures (SLH-DSA)

Stateless hash-based signatures per FIPS 205. Security rests solely on hash-function
strength (no lattice assumptions), at the cost of larger signatures and slower signing.
Signatures are **detached** (message NOT embedded — unlike ML-DSA).

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
  print('SLH-DSA signature valid: $isValid');
}
```

### 4. AEAD Symmetric Encryption

Fast, authenticated symmetric encryption (AES-256-GCM / ChaCha20Poly1305 /
XChaCha20Poly1305). Prefer `xChaCha20Poly1305` when you cannot guarantee unique
12-byte nonces — its 24-byte random nonce is safe without a counter.

```dart
import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> encryptData() async {
  final plaintext = Uint8List.fromList(utf8.encode("Secret Data"));
  final key = Uint8List(32); // 256-bit key

  // Encrypt
  final ciphertext = await QuantumCrypto.aead.encrypt(
    algorithm: AeadAlgorithm.aes256Gcm,
    key: key,
    plaintext: plaintext,
  );

  // Decrypt
  final decrypted = await QuantumCrypto.aead.decrypt(
    algorithm: AeadAlgorithm.aes256Gcm,
    key: key,
    ciphertextWithNonce: ciphertext,
  );
}
```

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

---

## 🔬 Advanced Usage

### Defense-in-Depth with Hybrid KEM

For enhanced security, use the Hybrid KEM which combines classical X25519 Elliptic Curve cryptography with Post-Quantum ML-KEM. If a quantum computer breaks ML-KEM, the classical X25519 protects you. If an attacker solves X25519 today, the ML-KEM protects you against future quantum attacks!

```dart
final hybridKeyPair = await QuantumCrypto.hybrid.generateKeyPair(
  HybridKemAlgorithm.mlKem768X25519
);

final result = await QuantumCrypto.hybrid.encapsulate(
  algorithm: HybridKemAlgorithm.mlKem768X25519,
  mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
  x25519PublicKey: hybridKeyPair.x25519PublicKey,
);
```

### Sign-then-Encrypt Secure Messaging

Send highly secure messages combining AEAD encryption (AES-256-GCM / ChaCha20Poly1305), ML-KEM exchange, and ML-DSA signatures automatically.

```dart
final package = await QuantumCrypto.messaging.signAndEncrypt(
  message: Uint8List.fromList(utf8.encode("Top Secret")),
  senderDsaSecretKey: myDsaSecretKey,
  recipientMlKemPublicKey: targetKemPublicKey,
  recipientX25519PublicKey: targetX25519PublicKey, // Optional Hybrid
);

// Decrypt on the other side
final originalMessage = await QuantumCrypto.messaging.decryptAndVerify(
  package: package,
  recipientMlKemSecretKey: myKemSecretKey,
  recipientX25519SecretKey: myX25519SecretKey,
  senderDsaPublicKey: senderDsaPublicKey,
);
```

### Streaming AEAD Encryption

For encrypting large payloads chunk-by-chunk without loading everything into memory at once.

```dart
final encryptedStream = await QuantumCrypto.streaming.streamEncrypt(
  algorithm: AeadAlgorithm.chaCha20Poly1305,
  key: key,
  plaintext: largeData,
  chunkSize: 65536, // Optional: Process in 64KB chunks
);

final decryptedStream = await QuantumCrypto.streaming.streamDecrypt(
  key: key,
  encryptedData: encryptedStream,
);
```

### Key Derivation Function (HKDF)

Derive strong, cryptographically secure keys from shared secrets.
Defaults to HKDF-SHA-256; pass `hash:` for SHA-384 / SHA-512.

```dart
final derivedKey = await QuantumCrypto.kdf.derive(
  sharedSecret: kemSharedSecret,
  info: Uint8List.fromList(utf8.encode("app_encryption_key")),
  outputLength: 32, // Output 32 bytes (256 bits)
);

// With explicit digest selection:
final derivedKey512 = await QuantumCrypto.kdf.derive(
  sharedSecret: kemSharedSecret,
  info: Uint8List.fromList(utf8.encode("app_encryption_key")),
  outputLength: 64,
  hash: HkdfHash.sha512,
);
```

### Deterministic Seed Generation

Generate master seeds and deterministically derive specific keys (useful for hierarchical wallets or secure device storage).

```dart
// 1. Generate a secure master seed
final masterSeed = await QuantumCrypto.seed.generateSeed();

// 2. Derive specific keys deterministically
final mlKemKey = await QuantumCrypto.seed.deriveKey(
  seed: masterSeed,
  purpose: "ml-kem-key",
  keyIndex: 0,
);

final x25519Key = await QuantumCrypto.seed.deriveX25519Key(
  seed: masterSeed,
  keyIndex: 0,
);

final aeadKey = await QuantumCrypto.seed.deriveAeadKey(
  seed: masterSeed,
  keyIndex: 0,
);
```

---

## ⚡ Performance Benchmarks

The **Quantum-Crypto** library runs its cryptography in native Rust and crosses to Dart over FFI, so even heavy 1024-dimensional lattice operations stay off the UI thread.

### 📊 Comprehensive Execution Benchmarks

Measured with the in-repo Dart benchmark harness: 100 warmup + 1000 timed iterations per operation, calling the Rust engine over FFI. Reproduce on your machine with:

```bash
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
| **SLH-DSA-SHA2-128f** | KeyGen | 354.5 | 326.0 | 671.0 | 337.0 | 2821.1 |
| **SLH-DSA-SHA2-128f** | Sign | 7400.0 | 6665.0 | 10569.0 | 7366.0 | 135.1 |
| **SLH-DSA-SHA2-128f** | Verify | 684.3 | 638.0 | 951.0 | 654.0 | 1461.3 |
| **SLH-DSA-SHA2-128f** | Roundtrip | 8525.5 | 7912.0 | 10089.0 | 8492.0 | 117.3 |
| **SLH-DSA-SHA2-192f** | KeyGen | 517.9 | 449.0 | 748.0 | 486.0 | 1930.9 |
| **SLH-DSA-SHA2-192f** | Sign | 11482.8 | 10744.0 | 13374.0 | 11430.0 | 87.1 |
| **SLH-DSA-SHA2-192f** | Verify | 1029.8 | 899.0 | 1392.0 | 1046.0 | 971.1 |
| **SLH-DSA-SHA2-192f** | Roundtrip | 13203.0 | 12227.0 | 17817.0 | 13172.0 | 75.7 |
| **SLH-DSA-SHA2-256f** | KeyGen | 1393.6 | 1194.0 | 2272.0 | 1399.0 | 717.6 |
| **SLH-DSA-SHA2-256f** | Sign | 24150.2 | 23015.0 | 25731.0 | 24092.0 | 41.4 |
| **SLH-DSA-SHA2-256f** | Verify | 1165.9 | 972.0 | 6192.0 | 1177.0 | 857.7 |
| **SLH-DSA-SHA2-256f** | Roundtrip | 26899.2 | 25371.0 | 33231.0 | 26879.0 | 37.2 |
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
| **Deterministic Key** | Derive (Kem) | 40.3 | 37.0 | 316.0 | 39.0 | 24829.9 |
| **Sign-then-Encrypt Pipeline** | EncryptAndSign | 252.5 | 176.0 | 830.0 | 234.0 | 3959.7 |
| **Sign-then-Encrypt Pipeline** | VerifyAndDecr | 166.5 | 152.0 | 389.0 | 158.0 | 6006.4 |

---
## 🤝 Contributing

Contributions are welcome! Here’s how to get started:

1.  Fork the repository.
2.  Create a new branch: `git checkout -b feature/YourFeature`
3.  Commit your changes: `git commit -m "Add amazing feature"`
4.  Push to your branch: `git push origin feature/YourFeature`
5.  Open a pull request.
> 💡 Please read our **[Contributing Guidelines](CONTRIBUTING.md)** and open an issue first for major feature ideas or changes.


---
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
