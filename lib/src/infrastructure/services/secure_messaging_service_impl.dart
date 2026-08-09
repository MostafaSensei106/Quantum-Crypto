import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/secure_messaging_service.dart';
import 'package:quantum_crypto/src/core/models/secure_package.dart';
import '../../rust/api/secure_messaging_api.dart' as rust_api;
import '../../rust/api/dsa_api.dart' as dsa_rust_api;
import '../../rust/api/hybrid_kem_api.dart' as hybrid_rust_api;
import '../../rust/api/aead_api.dart' as aead_rust_api;

final class SecureMessagingServiceImpl implements SecureMessagingService {
  const SecureMessagingServiceImpl();

  @override
  Future<SecurePackage> signAndEncrypt({
    required Uint8List message,
    required Uint8List senderDsaSecretKey,
    required Uint8List recipientMlKemPublicKey,
    required Uint8List recipientX25519PublicKey,
    DsaAlgorithm dsaAlgorithm = DsaAlgorithm.mlDsa65,
    HybridKemAlgorithm kemAlgorithm = HybridKemAlgorithm.mlKem768X25519,
    AeadAlgorithm aeadAlgorithm = AeadAlgorithm.aes256Gcm,
  }) async {
    final result = await rust_api.signThenEncrypt(
      dsaAlgorithm: _mapDsaAlgorithm(dsaAlgorithm),
      kemAlgorithm: _mapKemAlgorithm(kemAlgorithm),
      aeadAlgorithm: _mapAeadAlgorithm(aeadAlgorithm),
      message: message,
      senderDsaSecretKey: senderDsaSecretKey,
      recipientMlkemPublicKey: recipientMlKemPublicKey,
      recipientX25519PublicKey: recipientX25519PublicKey,
    );

    return SecurePackage(
      mlKemCiphertext: Uint8List.fromList(result.mlkemCiphertext),
      x25519EphemeralPk: Uint8List.fromList(result.x25519EphemeralPk),
      encryptedPayload: Uint8List.fromList(result.encryptedPayload),
      dsaAlgorithm: dsaAlgorithm,
      kemAlgorithm: kemAlgorithm,
      aeadAlgorithm: aeadAlgorithm,
    );
  }

  @override
  Future<Uint8List> decryptAndVerify({
    required SecurePackage package,
    required Uint8List recipientMlKemSecretKey,
    required Uint8List recipientX25519SecretKey,
    required Uint8List senderDsaPublicKey,
  }) async {
    final result = await rust_api.decryptThenVerify(
      packageMlkemCiphertext: package.mlKemCiphertext,
      packageX25519EphemeralPk: package.x25519EphemeralPk,
      packageEncryptedPayload: package.encryptedPayload,
      dsaAlgorithm: _mapDsaAlgorithm(package.dsaAlgorithm),
      kemAlgorithm: _mapKemAlgorithm(package.kemAlgorithm),
      aeadAlgorithm: _mapAeadAlgorithm(package.aeadAlgorithm),
      recipientMlkemSecretKey: recipientMlKemSecretKey,
      recipientX25519SecretKey: recipientX25519SecretKey,
      senderDsaPublicKey: senderDsaPublicKey,
    );
    return Uint8List.fromList(result);
  }

  dsa_rust_api.TargetDsaAlgorithm _mapDsaAlgorithm(DsaAlgorithm algo) {
    return switch (algo) {
      DsaAlgorithm.mlDsa44 => dsa_rust_api.TargetDsaAlgorithm.mlDsa44,
      DsaAlgorithm.mlDsa65 => dsa_rust_api.TargetDsaAlgorithm.mlDsa65,
      DsaAlgorithm.mlDsa87 => dsa_rust_api.TargetDsaAlgorithm.mlDsa87,
    };
  }

  hybrid_rust_api.TargetHybridKemAlgorithm _mapKemAlgorithm(
      HybridKemAlgorithm algo) {
    return switch (algo) {
      HybridKemAlgorithm.mlKem512X25519 =>
        hybrid_rust_api.TargetHybridKemAlgorithm.mlKem512X25519,
      HybridKemAlgorithm.mlKem768X25519 =>
        hybrid_rust_api.TargetHybridKemAlgorithm.mlKem768X25519,
      HybridKemAlgorithm.mlKem1024X25519 =>
        hybrid_rust_api.TargetHybridKemAlgorithm.mlKem1024X25519,
    };
  }

  aead_rust_api.TargetAeadAlgorithm _mapAeadAlgorithm(AeadAlgorithm algo) {
    return switch (algo) {
      AeadAlgorithm.aes256Gcm => aead_rust_api.TargetAeadAlgorithm.aes256Gcm,
      AeadAlgorithm.chaCha20Poly1305 =>
        aead_rust_api.TargetAeadAlgorithm.chaCha20Poly1305,
    };
  }
}
