import 'dart:typed_data';
import 'package:quantum_crypto/src/core/interfaces/key_serialization_service.dart';
import '../../rust/api/key_serialization_api.dart' as rust_api;

final class KeySerializationServiceImpl implements KeySerializationService {
  const KeySerializationServiceImpl();

  @override
  Future<String> bytesToHex(Uint8List data) async {
    return await rust_api.bytesToHex(data: data);
  }

  @override
  Future<Uint8List> hexToBytes(String hex) async {
    final result = await rust_api.hexToBytes(hex: hex);
    return Uint8List.fromList(result);
  }

  @override
  Future<String> bytesToBase64(Uint8List data) async {
    return await rust_api.bytesToBase64(data: data);
  }

  @override
  Future<Uint8List> base64ToBytes(String encoded) async {
    final result = await rust_api.base64ToBytes(encoded: encoded);
    return Uint8List.fromList(result);
  }

  @override
  Future<String> bytesToBase64UrlSafe(Uint8List data) async {
    return await rust_api.bytesToBase64UrlSafe(data: data);
  }

  @override
  Future<Uint8List> base64UrlSafeToBytes(String encoded) async {
    final result = await rust_api.base64UrlSafeToBytes(encoded: encoded);
    return Uint8List.fromList(result);
  }
}
