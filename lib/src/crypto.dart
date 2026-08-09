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
import 'package:quantum_crypto/src/rust/frb_generated.dart';

/// PqCrypto — Unified Post-Quantum Cryptography Facade.
///
/// Provides both high-level and low-level access to:
/// - ML-KEM (Key Encapsulation)
/// - ML-DSA (Digital Signatures)
/// - Hybrid KEM (ML-KEM + X25519)
/// - AEAD Encryption (AES-256-GCM / ChaCha20-Poly1305)
/// - Key Serialization (Hex, Base64)
/// - Secure Messaging (Sign-then-Encrypt)
abstract final class QuantumCrypto {
  static bool _isInitialized = false;

  static Future<void> init() async {
    if (_isInitialized) return;
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
}
