import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:quantum_crypto/src/core/interfaces/aead_service.dart';
import 'package:quantum_crypto/src/core/interfaces/dsa_service.dart';
import 'package:quantum_crypto/src/core/interfaces/hybrid_kem_service.dart';
import 'package:quantum_crypto/src/core/interfaces/kem_service.dart';
import 'package:quantum_crypto/src/core/interfaces/key_serialization_service.dart';
import 'package:quantum_crypto/src/core/interfaces/secure_messaging_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/aead_service_impl.dart';
import 'package:quantum_crypto/src/infrastructure/services/hybrid_kem_service_impl.dart';
import 'package:quantum_crypto/src/infrastructure/services/key_serialization_service_impl.dart';
import 'package:quantum_crypto/src/infrastructure/services/ml_dsa_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/ml_kem_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/secure_messaging_service_impl.dart';
import 'package:quantum_crypto/src/core/interfaces/streaming_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/streaming_service_impl.dart';
import 'package:quantum_crypto/src/core/interfaces/kdf_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/kdf_service_impl.dart';
import 'package:quantum_crypto/src/core/interfaces/seed_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/seed_service_impl.dart';
import 'package:quantum_crypto/src/core/interfaces/benchmark_service.dart';
import 'package:quantum_crypto/src/infrastructure/services/benchmark_service_impl.dart';
import 'package:quantum_crypto/src/rust/frb_generated.dart';

/// QuantumCrypto — Unified Post-Quantum Cryptography Facade.
///
/// Provides both high-level and low-level access to:
/// - ML-KEM (Key Encapsulation)
/// - ML-DSA (Digital Signatures)
/// - Hybrid KEM (ML-KEM + X25519)
/// - AEAD Encryption (AES-256-GCM / ChaCha20-Poly1305)
/// - Key Serialization (Hex, Base64)
/// - Secure Messaging (Sign-then-Encrypt)
abstract final class QuantumCrypto {
  const QuantumCrypto._();
  static bool _isInitialized = false;

  /// Initializes the underlying Rust FFI bridge and cryptographic context.
  ///
  /// **WARNING**: This must be called before performing any cryptographic operations.
  /// Failure to do so may result in native bridge errors.
  ///
  /// Example:
  /// ```dart
  /// void main() async {
  ///   await QuantumCrypto.init();
  ///   runApp(MyApp());
  /// }
  /// ```
  /// On web, the WASM artifacts are pre-loaded from the Flutter asset path
  /// (`assets/packages/quantum_crypto/web/pkg/`) so that `flutter build web`
  /// automatically bundles them — no manual copy step needed.
  ///
  static Future<void> init() async {
    if (_isInitialized) return;
    if (const bool.fromEnvironment('dart.library.html')) {
      final lib = await loadExternalLibrary(
        const ExternalLibraryLoaderConfig(
          stem: 'quantum_crypto',
          ioDirectory: 'rust/target/release/',
          webPrefix: 'assets/packages/quantum_crypto/web/pkg/',
        ),
      );
      return RustLib.init(externalLibrary: lib);
    }
    await RustLib.init();
    _isInitialized = true;
  }
  // === Low-Level Services ===

  /// ML-KEM Key Encapsulation Mechanism service.
  static const KemService kem = MlKemService();

  /// ML-DSA Digital Signature Algorithm service.
  static const DsaService dsa = MlDsaService();

  /// Hybrid KEM (ML-KEM + X25519) service.
  static const HybridKemService hybrid = HybridKemServiceImpl();

  /// AEAD symmetric encryption service.
  static const AeadService aead = AeadServiceImpl();

  /// Key serialization utilities (Hex, Base64).
  static const KeySerializationService keys = KeySerializationServiceImpl();

  // === High-Level Services ===

  /// Secure messaging: Sign-then-Encrypt / Decrypt-then-Verify.
  static const SecureMessagingService messaging = SecureMessagingServiceImpl();

  /// Streaming AEAD encryption service for large files.
  static const StreamingService streaming = StreamingServiceImpl();

  /// HKDF key derivation service.
  static const KdfService kdf = KdfServiceImpl();

  /// Seed-based deterministic key derivation service.
  static const SeedService seed = SeedServiceImpl();

  /// Cryptographic benchmark suite.
  static const BenchmarkService benchmark = BenchmarkServiceImpl();
}
