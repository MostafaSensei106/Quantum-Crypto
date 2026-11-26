import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

void main() {
  setUpAll(QuantumCrypto.init);
  test('native DSA signs without private key export and disposes safely',
      () async {
    final message = Uint8List.fromList([1, 2, 3]);
    final key = await QuantumCrypto.nativeKeys
        .generateDsa(algorithm: DsaAlgorithm.mlDsa65, exportable: false);
    final signature = await key.sign(message);
    final publicKey = await key.publicKey();
    expect(
        await QuantumCrypto.dsa.verify(
            algorithm: DsaAlgorithm.mlDsa65,
            message: message,
            signature: signature,
            publicKey: publicKey),
        isTrue);
    await expectLater(key.exportSecret(), throwsA(anything));
    await Future.wait([key.dispose(), key.dispose()]);
    await expectLater(key.sign(message), throwsA(anything));
  });

  test('export is opt-in; imported keys preserve public binding', () async {
    final key = await QuantumCrypto.nativeKeys
        .generateDsa(algorithm: DsaAlgorithm.mlDsa44, exportable: true);
    final exported = await key.exportSecret();
    final imported = await QuantumCrypto.nativeKeys.importKey(
        algorithm: NativeKeyAlgorithm.mlDsa44,
        secretKey: exported.secretKey,
        publicKey: await key.publicKey());
    expect(await imported.sign(Uint8List(0)), isNotEmpty);
    await expectLater(imported.exportSecret(), throwsA(anything));
    await key.dispose();
    await imported.dispose();
  });

  test('native shared secret handles derive interoperable AEAD keys', () async {
    final recipient = await QuantumCrypto.nativeKeys
        .generateHybrid(algorithm: HybridKemAlgorithm.mlKem768X25519);
    final enc = await QuantumCrypto.nativeKeys.encapsulateHybrid(
        algorithm: HybridKemAlgorithm.mlKem768X25519,
        mlKemPublicKey: await recipient.publicKey(),
        x25519PublicKey: await recipient.secondaryPublicKey());
    final recovered = await recipient.decapsulate(
        ciphertext: enc.ciphertext, x25519EphemeralPk: enc.x25519EphemeralPk);
    final context = Uint8List.fromList([1]);
    final a = await enc.sharedSecret.deriveAead(
        algorithm: AeadAlgorithm.xChaCha20Poly1305, context: context);
    final b = await recovered.deriveAead(
        algorithm: AeadAlgorithm.xChaCha20Poly1305, context: context);
    final message = Uint8List.fromList([1, 2, 3]);
    final ct = await a.encrypt(message, associatedData: context);
    expect(await b.decrypt(ct, associatedData: context), message);
    await expectLater(b.decrypt(ct), throwsA(anything));
    final stream = await a.streamEncrypt(message, chunkSize: 1);
    expect(await b.streamDecrypt(stream), message);
    for (final key in [a, b, enc.sharedSecret, recovered, recipient]) {
      await key.dispose();
    }
  });

  test('both native messaging modes bind context and reject old versions',
      () async {
    final sender = await QuantumCrypto.nativeKeys
        .generateDsa(algorithm: DsaAlgorithm.mlDsa65);
    final recipient = await QuantumCrypto.nativeKeys
        .generateHybrid(algorithm: HybridKemAlgorithm.mlKem768X25519);
    final message = Uint8List.fromList([4, 5, 6]);
    final aad = Uint8List.fromList([7]);
    final p = await sender.signAndEncrypt(
        message: message,
        recipientAlgorithm: HybridKemAlgorithm.mlKem768X25519,
        recipientMlKemPublicKey: await recipient.publicKey(),
        recipientX25519PublicKey: await recipient.secondaryPublicKey(),
        associatedData: aad);
    expect(
        await recipient.decryptAndVerify(
            package: p,
            senderDsaPublicKey: await sender.publicKey(),
            associatedData: aad),
        message);
    await expectLater(
        recipient.decryptAndVerify(
            package: p, senderDsaPublicKey: await sender.publicKey()),
        throwsA(anything));
    final q = await sender.encryptAndSign(
        message: message,
        recipientAlgorithm: HybridKemAlgorithm.mlKem768X25519,
        recipientMlKemPublicKey: await recipient.publicKey(),
        recipientX25519PublicKey: await recipient.secondaryPublicKey(),
        associatedData: aad);
    expect(
        await recipient.verifyAndDecrypt(
            package: q,
            senderDsaPublicKey: await sender.publicKey(),
            associatedData: aad),
        message);
    final old = SecurePackage(
        version: 1,
        mlKemCiphertext: p.mlKemCiphertext,
        x25519EphemeralPk: p.x25519EphemeralPk,
        encryptedPayload: p.encryptedPayload,
        dsaAlgorithm: p.dsaAlgorithm,
        kemAlgorithm: p.kemAlgorithm,
        aeadAlgorithm: p.aeadAlgorithm);
    await expectLater(
        recipient.decryptAndVerify(
            package: old,
            senderDsaPublicKey: await sender.publicKey(),
            associatedData: aad),
        throwsA(anything));
    await sender.dispose();
    await recipient.dispose();
  });

  test('read-only owned key buffers and identity equality', () {
    final source = Uint8List.fromList([1]);
    final key = PqcKeyPair(publicKey: source, secretKey: source);
    source[0] = 2;
    expect(key.secretKey[0], 1);
    expect(() => key.secretKey[0] = 3, throwsUnsupportedError);
    expect(key, isNot(PqcKeyPair(publicKey: source, secretKey: source)));
  });
}
