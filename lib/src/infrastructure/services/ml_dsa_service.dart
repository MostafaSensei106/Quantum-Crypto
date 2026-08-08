import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/dsa_service.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

import '../../rust/api/dsa_api.dart' as rust_api;

final class MlDsaService implements DsaService {
  const MlDsaService();

  @override
  Future<PqcKeyPair> generateKeyPair(DsaAlgorithm algorithm) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final dto = await rust_api.generateDsaKeypair(algorithm: rustAlgorithm);

    return PqcKeyPair(
      publicKey: Uint8List.fromList(dto.publicKey),
      secretKey: Uint8List.fromList(dto.secretKey),
    );
  }

  @override
  Future<Uint8List> sign({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List secretKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final signatureBytes = await rust_api.dsaSign(
      algorithm: rustAlgorithm,
      message: message,
      secretKey: secretKey,
    );

    return Uint8List.fromList(signatureBytes);
  }

  @override
  Future<bool> verify({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    return await rust_api.dsaVerify(
      algorithm: rustAlgorithm,
      message: message,
      signature: signature,
      publicKey: publicKey,
    );
  }

  rust_api.TargetDsaAlgorithm _mapToRustAlgorithm(DsaAlgorithm algorithm) {
    return switch (algorithm) {
      DsaAlgorithm.mlDsa44 => rust_api.TargetDsaAlgorithm.mlDsa44,
      DsaAlgorithm.mlDsa65 => rust_api.TargetDsaAlgorithm.mlDsa65,
      DsaAlgorithm.mlDsa87 => rust_api.TargetDsaAlgorithm.mlDsa87,
    };
  }
}
