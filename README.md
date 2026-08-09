<h1 align="center">Quantum-Crypto</h1>
<p align="center">
  <img src="https://socialify.git.ci/MostafaSensei106/Quantum-Crypto/image?custom_language=Rust&font=KoHo&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F138288138%3Fv%3D4&name=1&owner=1&pattern=Floating+Cogs&theme=Light" alt="Banner">
</p>

<p align="center">
  <strong>An advanced, Post-Quantum Cryptography suite for Flutter, powered by Rust.</strong><br>
  Future-proof your Flutter applications with implementations of <i>NIST-standardized algorithms</i> (ML-KEM, ML-DSA), <i>hybrid key exchanges</i>, and <i>secure messaging protocols</i>.
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
| **Algorithm Standards** | Legacy | Drafts / Unverified | **✅ Implements FIPS 203 / FIPS 204** |
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
  - Hybrid KEM: **X25519 + ML-KEM**
  - AEAD Encryption: **AES-256-GCM, ChaCha20Poly1305**
  - Data Processing: **Streaming Encryption, HKDF, Deterministic Seed Generation**

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

### 3. AEAD Symmetric Encryption

Fast, authenticated symmetric encryption (AES-256-GCM / ChaCha20Poly1305).

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

### 4. Key Serialization

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

```dart
final derivedKey = await QuantumCrypto.kdf.derive(
  sharedSecret: kemSharedSecret,
  info: Uint8List.fromList(utf8.encode("app_encryption_key")),
  outputLength: 32, // Output 32 bytes (256 bits)
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

The **Quantum-Crypto** library is meticulously optimized using Rust and FFI for blistering speed, even on heavy 1024-dimensional operations.

### 📊 Comprehensive Execution Benchmarks

The following benchmarks were generated using the internal benchmark suite running over 1000 iterations per step after a warmup phase. You can reproduce these results on your target platform by running:

```bash
flutter test test/benchmark_test.dart
```

| Algorithm / Operation | Step | Avg (μs) | Min (μs) | Max (μs) | Median (μs) | Ops/sec |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| **ML-KEM-512** | KeyGen | 109.5 | 85.0 | 827.0 | 105.0 | 9,134.1 |
| **ML-KEM-512** | Encapsulate | 95.9 | 82.0 | 561.0 | 93.0 | 10,423.2 |
| **ML-KEM-512** | Decapsulate | 87.5 | 74.0 | 340.0 | 84.0 | 11,424.9 |
| **ML-KEM-512** | Roundtrip | 212.5 | 169.0 | 520.0 | 209.0 | 4,705.5 |
| **ML-KEM-768** | KeyGen | 80.5 | 64.0 | 3,016.0 | 74.0 | 12,428.1 |
| **ML-KEM-768** | Encapsulate | 70.4 | 55.0 | 517.0 | 68.0 | 14,212.4 |
| **ML-KEM-768** | Decapsulate | 72.7 | 63.0 | 271.0 | 71.0 | 13,751.9 |
| **ML-KEM-768** | Roundtrip | 200.4 | 163.0 | 539.0 | 196.0 | 4,990.7 |
| **ML-KEM-1024** | KeyGen | 70.8 | 59.0 | 488.0 | 66.0 | 14,117.5 |
| **ML-KEM-1024** | Encapsulate | 64.9 | 56.0 | 335.0 | 63.0 | 15,402.9 |
| **ML-KEM-1024** | Decapsulate | 73.4 | 60.0 | 3,597.0 | 68.0 | 13,623.8 |
| **ML-KEM-1024** | Roundtrip | 202.8 | 180.0 | 557.0 | 198.0 | 4,930.3 |
| **ML-DSA-44** | KeyGen | 76.6 | 65.0 | 361.0 | 76.0 | 13,054.1 |
| **ML-DSA-44** | Sign | 125.1 | 74.0 | 2,683.0 | 108.0 | 7,993.0 |
| **ML-DSA-44** | Verify | 72.7 | 64.0 | 284.0 | 69.0 | 13,763.7 |
| **ML-DSA-44** | Roundtrip | 273.6 | 211.0 | 636.0 | 259.0 | 3,655.5 |
| **ML-DSA-65** | KeyGen | 90.6 | 81.0 | 292.0 | 86.0 | 11,032.4 |
| **ML-DSA-65** | Sign | 164.0 | 91.0 | 630.0 | 142.0 | 6,099.2 |
| **ML-DSA-65** | Verify | 96.3 | 80.0 | 3,678.0 | 92.0 | 10,383.8 |
| **ML-DSA-65** | Roundtrip | 370.1 | 258.0 | 897.0 | 351.0 | 2,702.3 |
| **ML-DSA-87** | KeyGen | 121.5 | 104.0 | 502.0 | 115.0 | 8,232.3 |
| **ML-DSA-87** | Sign | 190.1 | 116.0 | 4,441.0 | 165.0 | 5,260.6 |
| **ML-DSA-87** | Verify | 113.1 | 101.0 | 354.0 | 108.0 | 8,839.2 |
| **ML-DSA-87** | Roundtrip | 434.7 | 330.0 | 901.0 | 412.0 | 2,300.6 |
| **Hybrid ML-KEM-512** | KeyGen | 74.4 | 65.0 | 353.0 | 72.0 | 13,439.2 |
| **Hybrid ML-KEM-512** | Encapsulate | 124.2 | 111.0 | 372.0 | 119.0 | 8,050.9 |
| **Hybrid ML-KEM-512** | Decapsulate | 106.8 | 97.0 | 990.0 | 101.0 | 9,362.7 |
| **Hybrid ML-KEM-512** | Roundtrip | 308.9 | 275.0 | 3,768.0 | 300.0 | 3,237.7 |
| **Hybrid ML-KEM-768** | KeyGen | 79.5 | 70.0 | 263.0 | 76.0 | 12,571.5 |
| **Hybrid ML-KEM-768** | Encapsulate | 128.1 | 115.0 | 378.0 | 122.0 | 7,804.6 |
| **Hybrid ML-KEM-768** | Decapsulate | 113.1 | 102.0 | 307.0 | 107.0 | 8,839.7 |
| **Hybrid ML-KEM-768** | Roundtrip | 330.4 | 294.0 | 4,481.0 | 318.0 | 3,026.9 |
| **Hybrid ML-KEM-1024** | KeyGen | 82.7 | 76.0 | 411.0 | 79.0 | 12,087.5 |
| **Hybrid ML-KEM-1024** | Encapsulate | 134.1 | 120.0 | 317.0 | 127.0 | 7,459.7 |
| **Hybrid ML-KEM-1024** | Decapsulate | 122.3 | 110.0 | 451.0 | 117.0 | 8,178.3 |
| **Hybrid ML-KEM-1024** | Roundtrip | 351.6 | 311.0 | 3,554.0 | 343.0 | 2,844.4 |
| **AES-256-GCM (1 KB)** | Encrypt | 52.0 | 46.0 | 354.0 | 50.0 | 19,238.9 |
| **AES-256-GCM (1 KB)** | Decrypt | 51.0 | 43.0 | 325.0 | 49.0 | 19,604.8 |
| **AES-256-GCM (64 KB)** | Encrypt | 322.1 | 274.0 | 3,611.0 | 311.0 | 3,104.4 |
| **AES-256-GCM (64 KB)** | Decrypt | 307.0 | 271.0 | 631.0 | 297.0 | 3,256.8 |
| **AES-256-GCM (1 MB)** | Encrypt | 7,311.6 | 5,068.0 | 16,810.0 | 6,658.0 | 136.8 |
| **AES-256-GCM (1 MB)** | Decrypt | 6,862.7 | 5,669.0 | 12,551.0 | 6,547.0 | 145.7 |
| **ChaCha20-Poly1305 (1 KB)** | Encrypt | 52.1 | 36.0 | 364.0 | 50.0 | 19,210.8 |
| **ChaCha20-Poly1305 (1 KB)** | Decrypt | 51.1 | 47.0 | 335.0 | 49.0 | 19,576.8 |
| **ChaCha20-Poly1305 (64 KB)** | Encrypt | 307.6 | 268.0 | 643.0 | 306.0 | 3,251.0 |
| **ChaCha20-Poly1305 (64 KB)** | Decrypt | 304.3 | 262.0 | 4,459.0 | 299.0 | 3,286.0 |
| **ChaCha20-Poly1305 (1 MB)** | Encrypt | 6,051.5 | 4,966.0 | 13,543.0 | 5,781.0 | 165.2 |
| **ChaCha20-Poly1305 (1 MB)** | Decrypt | 6,913.9 | 5,543.0 | 14,450.0 | 6,517.0 | 144.6 |
| **Streaming Encrypt (1MB, 64k)** | Process | 6,169.9 | 4,574.0 | 13,886.0 | 5,835.0 | 162.1 |
| **Streaming Decrypt (1MB, 64k)** | Process | 6,134.9 | 4,662.0 | 15,158.0 | 5,907.0 | 163.0 |
| **HKDF-SHA256** | Derive | 50.4 | 44.0 | 525.0 | 49.0 | 19,849.1 |
| **Seed Generation** | Generate | 53.3 | 41.0 | 4,682.0 | 47.0 | 18,766.0 |
| **Deterministic Key** | Derive (Kem) | 53.7 | 48.0 | 309.0 | 52.0 | 18,630.0 |
| **Sign-then-Encrypt Pipeline** | EncryptAndSign | 271.3 | 186.0 | 701.0 | 251.0 | 3,685.9 |
| **Sign-then-Encrypt Pipeline** | VerifyAndDecr | 189.7 | 159.0 | 3,934.0 | 182.0 | 5,272.8 |

---

## 🧪 Testing

The library includes a robust suite of production-grade tests, including correctness verification and security regression tests (tamper checks).

```bash
# First, ensure your Rust library is compiled for your host machine
cd rust && cargo build --release
cd ..

# Run all tests, including KEM, DSA, Hybrid, and Benchmarks
flutter test
```

### Running Specific Tests
```bash
# Run only ML-KEM correctness tests
flutter test test/ml_kem_test.dart

# Run local performance benchmarks
flutter test test/benchmark_test.dart
```

---

## 🤝 Contributing

Contributions are welcome! Here’s how to get started:

1.  Fork the repository.
2.  Create a new branch: `git checkout -b feature/YourFeature`
3.  Commit your changes: `git commit -m "Add amazing feature"`
4.  Push to your branch: `git push origin feature/YourFeature`
5.  Open a pull request.

---
## ⚖️ License

This project is licensed under the **GPL-3.0 License**.
See the [LICENSE](LICENSE) file for full details.

<p align="center">
  Made with ❤️ by <a href="https://github.com/MostafaSensei106">MostafaSensei106</a>
</p>
