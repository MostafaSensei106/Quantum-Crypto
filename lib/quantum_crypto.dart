library;

import 'package:quantum_crypto/src/rust/frb_generated.dart' show RustLib;

export 'src/core/enums/kem_algorithm.dart';
export 'src/core/interfaces/kem_service.dart';
export 'src/core/models/encapsulation_result.dart';
export 'src/core/models/key_pair.dart';

export 'src/core/enums/dsa_algorithm.dart';
export 'src/core/interfaces/dsa_service.dart';

// Infrastructure Services exports
export 'src/infrastructure/services/ml_dsa_service.dart';
export 'src/infrastructure/services/ml_kem_service.dart';

abstract final class QuantumCrypto {
  static bool _isInitialized = false;

  static Future<void> init() async {
    if (_isInitialized) return;
    await RustLib.init();
    _isInitialized = true;
  }
}
