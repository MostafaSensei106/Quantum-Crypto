# Migrating to 0.0.3

This Dev Preview deliberately changes formats and APIs despite the patch-sized
version. Rebuild the Rust binary and regenerate/package the matching Dart FFI
bindings together; mixing old native artifacts with the new bindings is invalid.
No publication or tag is implied by updating the package metadata.

- Streaming v1 cannot be opened by 0.0.3. There is no automatic legacy fallback.
- Hybrid KEM v2 changes derived secrets and prefixes the ML-KEM ciphertext with
  version byte 2. Keep this byte. Decapsulation now requires the recipient's
  ML-KEM and X25519 public keys as well as secret keys.
- Message packages require `version: 2`; creation with raw signing keys now also
  requires `senderDsaPublicKey`. Opening requires the recipient public keys.
  If using AAD, supply identical bytes when creating and opening the package.
- The message signature transcript changed; old signatures/packages cannot be
  upgraded by changing a version number. Persist package version alongside all
  ciphertext and algorithm fields.
- `PqcKeyPair` / `HybridKeyPair` use identity equality and are no longer `const`.
  Encapsulation result constructors also lose `const` to own read-only snapshots.
  Bytes are owned read-only snapshots. Do not use secret-byte equality or hashes
  as identifiers; use a separately defined public-key fingerprint.
- AEAD gains optional `associatedData`. Omitting it preserves the ordinary
  one-shot empty-AAD behavior and wire layout.

If legacy data must be recovered, use a pinned old build in an isolated migration
tool, on trusted local input, then re-encrypt using 0.0.3. Streaming v1 metadata
and completion cannot be authenticated retrospectively. Recovering old ciphertext
does not restore confidentiality or integrity already lost through nonce reuse;
restore from a trusted source where possible and rotate exposed keys. Keep
backups and verify output before replacing data. This release does not ship a
legacy decoder inside the default library.

Prefer `QuantumCrypto.nativeKeys` for new keys. Existing byte-key operations
remain available. Importing old keys is explicit and cannot remove existing Dart
copies. Handles default to non-exportable, have fixed usage policies and are
process-local. If persistence requires export, opt in when creating/importing
and protect the exported bytes in an application-controlled secure store.
