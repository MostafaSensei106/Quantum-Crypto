# Native key management

`QuantumCrypto.nativeKeys` returns a `NativeKey` whose secret lives in Rust.
The public facade supports `generateDsa`, `generateSlhDsa`, `generateKem`,
`generateHybrid`, `generateAead`, `generateSeed`, generic `generate`, and
explicit `importKey`. Generated/imported keys have immutable algorithm,
exportability and usage policies. `usages: []` permits no secret operations.

| Key type | Default usages | Operations |
| --- | --- | --- |
| ML-DSA / SPHINCS+ | sign | `sign`; ML-DSA also supports message protection |
| ML-KEM / hybrid | decapsulate | `decapsulate`; hybrid also opens message packages |
| AEAD | encrypt, decrypt | `encrypt`, `decrypt`, `streamEncrypt`, `streamDecrypt` |
| Seed / shared secret | derive | `deriveAead` |

All types provide `publicKey`, `secondaryPublicKey`, `exportSecret`, `dispose`.
Symmetric keys and seeds return an empty public key. Hybrid keys expose their
X25519 public component through `secondaryPublicKey`.

`encapsulateKem` and `encapsulateHybrid` accept public keys and return ciphertext,
optional X25519 ephemeral public key and a **native shared-secret handle**.
The recipient's `decapsulate` returns another shared-secret handle. Derive AEAD
handles with the same algorithm, nonempty application context and key index on
both ends. Neither path needs to return the shared secret to Dart.

`exportable` defaults to false. `exportSecret()` fails unless it was enabled
at generation/import. Export returns `secretKey` and `secondarySecretKey`;
only hybrid keys have the secondary component. Once exported, bytes reside in
Dart and cannot be guaranteed to be erased. Import cannot erase original Dart
copies. A non-exportable parent cannot derive an exportable child. Decapsulated
shared secrets inherit recipient exportability; encapsulated shared-secret
exportability is selected explicitly by the caller and defaults to false.

Derived AEAD keys use HKDF-SHA256, with the native-v2 salt and an info field
containing a domain label, algorithm ID, length-prefixed application context
and a big-endian key index. Import validates key lengths and asymmetric key
pairing; it is not a certificate or an identity check.

The underlying opaque object contains shared native ownership of a
`Mutex<Option<Material>>`, and secret vectors use `Zeroizing`. Operations hold
the mutex while using the secret. `dispose()` calls native `close`, which waits
for existing operations, drops the material, and makes subsequent operations
fail. Native clones share that state; closing an alias closes them all. A child
key is independent: disposing a parent does not revoke existing children.
There is no multi-key lock acquisition or nested locking of two handles.

Use `try/finally` and `await key.dispose()`. Disposal is idempotent. The bridge's
finalizer releases native ownership when the Dart object is collected; timing
is nondeterministic. Concurrent operations and disposal can either finish before
close or fail after close. A successfully returned signature/plaintext is not
revoked by later disposal.

Handles are process-local software secrets, not platform keystore references,
hardware isolation, encrypted persistence or guaranteed locked memory. A process
attacker can still read native memory. See [threat model](threat-model.md).
