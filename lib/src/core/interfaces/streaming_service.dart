import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';

/// Service for streaming/chunked AEAD encryption of large data.
abstract interface class StreamingService {
  /// Encrypt data using streaming/chunked AEAD.
  /// Data is split into chunks (default 64KB) and each chunk
  /// is independently encrypted.
  Future<Uint8List> streamEncrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List plaintext,
    int? chunkSize,
  });

  /// Decrypt data that was encrypted with streaming/chunked AEAD.
  Future<Uint8List> streamDecrypt({
    required Uint8List key,
    required Uint8List encryptedData,
  });
}
