import 'dart:typed_data';

abstract interface class KeySerializationService {
  Future<String> bytesToHex(Uint8List data);
  Future<Uint8List> hexToBytes(String hex);
  Future<String> bytesToBase64(Uint8List data);
  Future<Uint8List> base64ToBytes(String encoded);
  Future<String> bytesToBase64UrlSafe(Uint8List data);
  Future<Uint8List> base64UrlSafeToBytes(String encoded);
}
