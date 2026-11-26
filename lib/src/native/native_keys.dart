// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import '../core/enums/aead_algorithm.dart';
import '../core/enums/dsa_algorithm.dart';
import '../core/enums/kem_algorithm.dart';
import '../core/enums/hybrid_kem_algorithm.dart';
import '../core/enums/slh_dsa_algorithm.dart';
import '../core/models/secure_package.dart';
import '../core/models/encrypt_then_sign_package.dart';
import '../rust/api/native_keys_api.dart' as native;
import '../rust/api/aead_api.dart' as aead;
import '../rust/api/dsa_api.dart' as dsa;
import '../rust/api/hybrid_kem_api.dart' as hybrid;
import '../rust/api/secure_messaging_api.dart' as messaging;
export '../rust/api/native_keys_api.dart'
    show NativeKeyAlgorithm, NativeKeyUsage;

/// Creates native secrets without returning private bytes to Dart.
/// Handles are process-local and must be disposed when no longer needed.
final class NativeKeysService {
  const NativeKeysService();

  Future<NativeKey> generate(
          {required native.NativeKeyAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) async =>
      NativeKey._(await native.generateNativeKey(
          algorithm: algorithm, exportable: exportable, usage: usages));

  Future<NativeKey> generateDsa(
          {required DsaAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) =>
      generate(
          algorithm: _dsaNative(algorithm),
          exportable: exportable,
          usages: usages);

  Future<NativeKey> generateKem(
          {required KemAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) =>
      generate(
          algorithm: _kemNative(algorithm),
          exportable: exportable,
          usages: usages);

  /// Hash-based signatures currently use the upstream SPHINCS+ implementation.
  Future<NativeKey> generateSlhDsa(
          {required SlhDsaAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) =>
      generate(
          algorithm: switch (algorithm) {
            SlhDsaAlgorithm.slhDsaSha2_128f =>
              native.NativeKeyAlgorithm.sphincsSha2128F,
            SlhDsaAlgorithm.slhDsaSha2_192f =>
              native.NativeKeyAlgorithm.sphincsSha2192F,
            SlhDsaAlgorithm.slhDsaSha2_256f =>
              native.NativeKeyAlgorithm.sphincsSha2256F,
          },
          exportable: exportable,
          usages: usages);

  Future<NativeKey> generateHybrid(
          {required HybridKemAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) =>
      generate(
          algorithm: _hybridNative(algorithm),
          exportable: exportable,
          usages: usages);

  Future<NativeKey> generateAead(
          {required AeadAlgorithm algorithm,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) =>
      generate(
          algorithm: _aeadNative(algorithm),
          exportable: exportable,
          usages: usages);

  Future<NativeKey> generateSeed({bool exportable = false}) => generate(
      algorithm: native.NativeKeyAlgorithm.seed, exportable: exportable);

  /// Importing raw bytes cannot erase copies that already exist in Dart.
  Future<NativeKey> importKey(
          {required native.NativeKeyAlgorithm algorithm,
          required Uint8List secretKey,
          Uint8List? secondarySecretKey,
          Uint8List? publicKey,
          Uint8List? secondaryPublicKey,
          bool exportable = false,
          List<native.NativeKeyUsage>? usages}) async =>
      NativeKey._(await native.importNativeKey(
          algorithm: algorithm,
          secretKey: secretKey,
          secondarySecretKey: secondarySecretKey ?? Uint8List(0),
          publicKey: publicKey ?? Uint8List(0),
          secondaryPublicKey: secondaryPublicKey ?? Uint8List(0),
          exportable: exportable,
          usage: usages));

  Future<NativeEncapsulation> encapsulateKem(
          {required KemAlgorithm algorithm,
          required Uint8List publicKey,
          bool exportable = false}) =>
      _encapsulate(_kemNative(algorithm), publicKey, Uint8List(0), exportable);

  Future<NativeEncapsulation> encapsulateHybrid(
          {required HybridKemAlgorithm algorithm,
          required Uint8List mlKemPublicKey,
          required Uint8List x25519PublicKey,
          bool exportable = false}) =>
      _encapsulate(_hybridNative(algorithm), mlKemPublicKey, x25519PublicKey,
          exportable);

  Future<NativeEncapsulation> _encapsulate(native.NativeKeyAlgorithm algorithm,
      Uint8List publicKey, Uint8List secondary, bool exportable) async {
    final result = await native.nativeEncapsulate(
        algorithm: algorithm,
        publicKey: publicKey,
        secondaryPublicKey: secondary,
        exportable: exportable);
    return NativeEncapsulation._(result.ciphertext, result.x25519EphemeralPk,
        NativeKey._(result.sharedSecret));
  }
}

/// A native-owned secret with fixed algorithm, usage and export policies.
/// Public keys can be read independently of secret export permission.
final class NativeKey {
  final native.NativeKey _handle;
  Future<void>? _disposal;
  NativeKey._(this._handle);

  Future<Uint8List> sign(Uint8List message) => _handle.sign(message: message);
  Future<Uint8List> publicKey() => _handle.publicKey();
  Future<Uint8List> secondaryPublicKey() => _handle.secondaryPublicKey();

  /// Explicitly copies secret bytes to Dart; fails for non-exportable keys.
  Future<NativeKeyExport> exportSecret() async {
    final result = await _handle.exportSecret();
    return NativeKeyExport._(result.secretKey, result.secondarySecretKey);
  }

  /// Waits for active operations and clears native secret buffers. Idempotent.
  /// The bridge's native finalizer is a backup, not a substitute for disposal.
  Future<void> dispose() => _disposal ??= _handle.close();

  Future<Uint8List> encrypt(Uint8List plaintext, {Uint8List? associatedData}) =>
      _handle.encrypt(
          plaintext: plaintext, associatedData: associatedData ?? Uint8List(0));
  Future<Uint8List> decrypt(Uint8List ciphertext,
          {Uint8List? associatedData}) =>
      _handle.decrypt(
          ciphertext: ciphertext,
          associatedData: associatedData ?? Uint8List(0));
  Future<Uint8List> streamEncrypt(Uint8List plaintext, {int? chunkSize}) =>
      _handle.streamEncrypt(plaintext: plaintext, chunkSize: chunkSize);
  Future<Uint8List> streamDecrypt(Uint8List ciphertext) =>
      _handle.streamDecrypt(ciphertext: ciphertext);

  Future<NativeKey> deriveAead(
          {required AeadAlgorithm algorithm,
          required Uint8List context,
          int keyIndex = 0,
          bool exportable = false}) async =>
      NativeKey._(await _handle.deriveAead(
          algorithm: switch (algorithm) {
            AeadAlgorithm.aes256Gcm => native.TargetNativeAead.aes256Gcm,
            AeadAlgorithm.chaCha20Poly1305 =>
              native.TargetNativeAead.chaCha20Poly1305,
            AeadAlgorithm.xChaCha20Poly1305 =>
              native.TargetNativeAead.xChaCha20Poly1305,
          },
          context: context,
          keyIndex: keyIndex,
          exportable: exportable));

  Future<NativeKey> decapsulate(
          {required Uint8List ciphertext,
          Uint8List? x25519EphemeralPk}) async =>
      NativeKey._(await _handle.decapsulate(
          ciphertext: ciphertext,
          x25519EphemeralPk: x25519EphemeralPk ?? Uint8List(0)));

  Future<SecurePackage> signAndEncrypt(
      {required Uint8List message,
      required HybridKemAlgorithm recipientAlgorithm,
      required Uint8List recipientMlKemPublicKey,
      required Uint8List recipientX25519PublicKey,
      AeadAlgorithm aeadAlgorithm = AeadAlgorithm.xChaCha20Poly1305,
      Uint8List? associatedData}) async {
    final p = await _handle.signAndEncrypt(
        message: message,
        recipientAlgorithm: _hybridRust(recipientAlgorithm),
        recipientMlkemPublicKey: recipientMlKemPublicKey,
        recipientX25519PublicKey: recipientX25519PublicKey,
        aeadAlgorithm: _aeadRust(aeadAlgorithm),
        associatedData: associatedData ?? Uint8List(0));
    return SecurePackage(
        version: p.version,
        mlKemCiphertext: p.mlkemCiphertext,
        x25519EphemeralPk: p.x25519EphemeralPk,
        encryptedPayload: p.encryptedPayload,
        dsaAlgorithm: _dsaPublic(p.dsaAlgorithm),
        kemAlgorithm: recipientAlgorithm,
        aeadAlgorithm: aeadAlgorithm);
  }

  Future<EncryptThenSignPackage> encryptAndSign(
      {required Uint8List message,
      required HybridKemAlgorithm recipientAlgorithm,
      required Uint8List recipientMlKemPublicKey,
      required Uint8List recipientX25519PublicKey,
      AeadAlgorithm aeadAlgorithm = AeadAlgorithm.xChaCha20Poly1305,
      Uint8List? associatedData}) async {
    final p = await _handle.encryptAndSign(
        message: message,
        recipientAlgorithm: _hybridRust(recipientAlgorithm),
        recipientMlkemPublicKey: recipientMlKemPublicKey,
        recipientX25519PublicKey: recipientX25519PublicKey,
        aeadAlgorithm: _aeadRust(aeadAlgorithm),
        associatedData: associatedData ?? Uint8List(0));
    return EncryptThenSignPackage(
        version: p.version,
        mlKemCiphertext: p.mlkemCiphertext,
        x25519EphemeralPk: p.x25519EphemeralPk,
        encryptedPayload: p.encryptedPayload,
        signature: p.signature,
        dsaAlgorithm: _dsaPublic(p.dsaAlgorithm),
        kemAlgorithm: recipientAlgorithm,
        aeadAlgorithm: aeadAlgorithm);
  }

  Future<Uint8List> decryptAndVerify(
          {required SecurePackage package,
          required Uint8List senderDsaPublicKey,
          Uint8List? associatedData}) =>
      _handle.decryptAndVerify(
          package: messaging.SecurePackageDto(
              version: package.version,
              mlkemCiphertext: package.mlKemCiphertext,
              x25519EphemeralPk: package.x25519EphemeralPk,
              encryptedPayload: package.encryptedPayload,
              dsaAlgorithm: _dsaRust(package.dsaAlgorithm),
              kemAlgorithm: _hybridRust(package.kemAlgorithm),
              aeadAlgorithm: _aeadRust(package.aeadAlgorithm)),
          senderDsaPublicKey: senderDsaPublicKey,
          associatedData: associatedData ?? Uint8List(0));

  Future<Uint8List> verifyAndDecrypt(
          {required EncryptThenSignPackage package,
          required Uint8List senderDsaPublicKey,
          Uint8List? associatedData}) =>
      _handle.verifyAndDecrypt(
          package: messaging.EncryptThenSignPackageDto(
              version: package.version,
              mlkemCiphertext: package.mlKemCiphertext,
              x25519EphemeralPk: package.x25519EphemeralPk,
              encryptedPayload: package.encryptedPayload,
              signature: package.signature,
              dsaAlgorithm: _dsaRust(package.dsaAlgorithm),
              kemAlgorithm: _hybridRust(package.kemAlgorithm),
              aeadAlgorithm: _aeadRust(package.aeadAlgorithm)),
          senderDsaPublicKey: senderDsaPublicKey,
          associatedData: associatedData ?? Uint8List(0));
}

final class NativeEncapsulation {
  final Uint8List ciphertext;
  final Uint8List x25519EphemeralPk;
  final NativeKey sharedSecret;
  NativeEncapsulation._(
      Uint8List ciphertext, Uint8List ephemeral, this.sharedSecret)
      : ciphertext = ciphertext.asUnmodifiableView(),
        x25519EphemeralPk = ephemeral.asUnmodifiableView();
}

/// Exported secrets reside in Dart memory and have no secure-erasure guarantee.
final class NativeKeyExport {
  final Uint8List secretKey;
  final Uint8List secondarySecretKey;
  NativeKeyExport._(this.secretKey, this.secondarySecretKey);
}

native.NativeKeyAlgorithm _dsaNative(DsaAlgorithm v) => switch (v) {
      DsaAlgorithm.mlDsa44 => native.NativeKeyAlgorithm.mlDsa44,
      DsaAlgorithm.mlDsa65 => native.NativeKeyAlgorithm.mlDsa65,
      DsaAlgorithm.mlDsa87 => native.NativeKeyAlgorithm.mlDsa87,
    };
native.NativeKeyAlgorithm _kemNative(KemAlgorithm v) => switch (v) {
      KemAlgorithm.mlKem512 => native.NativeKeyAlgorithm.mlKem512,
      KemAlgorithm.mlKem768 => native.NativeKeyAlgorithm.mlKem768,
      KemAlgorithm.mlKem1024 => native.NativeKeyAlgorithm.mlKem1024,
    };
native.NativeKeyAlgorithm _hybridNative(HybridKemAlgorithm v) => switch (v) {
      HybridKemAlgorithm.mlKem512X25519 =>
        native.NativeKeyAlgorithm.mlKem512X25519,
      HybridKemAlgorithm.mlKem768X25519 =>
        native.NativeKeyAlgorithm.mlKem768X25519,
      HybridKemAlgorithm.mlKem1024X25519 =>
        native.NativeKeyAlgorithm.mlKem1024X25519,
    };
native.NativeKeyAlgorithm _aeadNative(AeadAlgorithm v) => switch (v) {
      AeadAlgorithm.aes256Gcm => native.NativeKeyAlgorithm.aes256Gcm,
      AeadAlgorithm.chaCha20Poly1305 =>
        native.NativeKeyAlgorithm.chaCha20Poly1305,
      AeadAlgorithm.xChaCha20Poly1305 =>
        native.NativeKeyAlgorithm.xChaCha20Poly1305,
    };
aead.TargetAeadAlgorithm _aeadRust(AeadAlgorithm v) => switch (v) {
      AeadAlgorithm.aes256Gcm => aead.TargetAeadAlgorithm.aes256Gcm,
      AeadAlgorithm.chaCha20Poly1305 =>
        aead.TargetAeadAlgorithm.chaCha20Poly1305,
      AeadAlgorithm.xChaCha20Poly1305 =>
        aead.TargetAeadAlgorithm.xChaCha20Poly1305,
    };
hybrid.TargetHybridKemAlgorithm _hybridRust(HybridKemAlgorithm v) =>
    switch (v) {
      HybridKemAlgorithm.mlKem512X25519 =>
        hybrid.TargetHybridKemAlgorithm.mlKem512X25519,
      HybridKemAlgorithm.mlKem768X25519 =>
        hybrid.TargetHybridKemAlgorithm.mlKem768X25519,
      HybridKemAlgorithm.mlKem1024X25519 =>
        hybrid.TargetHybridKemAlgorithm.mlKem1024X25519,
    };
dsa.TargetDsaAlgorithm _dsaRust(DsaAlgorithm v) => switch (v) {
      DsaAlgorithm.mlDsa44 => dsa.TargetDsaAlgorithm.mlDsa44,
      DsaAlgorithm.mlDsa65 => dsa.TargetDsaAlgorithm.mlDsa65,
      DsaAlgorithm.mlDsa87 => dsa.TargetDsaAlgorithm.mlDsa87,
    };
DsaAlgorithm _dsaPublic(dsa.TargetDsaAlgorithm v) => switch (v) {
      dsa.TargetDsaAlgorithm.mlDsa44 => DsaAlgorithm.mlDsa44,
      dsa.TargetDsaAlgorithm.mlDsa65 => DsaAlgorithm.mlDsa65,
      dsa.TargetDsaAlgorithm.mlDsa87 => DsaAlgorithm.mlDsa87,
    };
