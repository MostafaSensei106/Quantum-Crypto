# Version 2 formats and constructions

These are project formats. Streaming uses RustCrypto's published STREAM
construction; the hybrid and message compositions remain unaudited project
constructions. No standards-conformance claim is made for those compositions.
Integers below are unsigned, big-endian; `field(x)` is `u32(len(x)) || x`.
Names are literal ASCII bytes, without a trailing NUL. Unknown versions fail.

## Streaming

Header: `2:u8 || algorithm:u8 || chunk_size:u32 || plaintext_len:u32 || salt:32
|| nonce_prefix:(nonce_len-5)`.
Algorithm IDs: AES-256-GCM=0, ChaCha20-Poly1305=1, XChaCha20-Poly1305=2.
Prefix lengths are 7, 7 and 19 respectively. Salt and prefix come from OsRng.

`stream_key = HKDF-SHA256(salt, input_key,
"Quantum-Crypto/STREAM-BE32/v2/" || algorithm:u8, 32)`.
RustCrypto `EncryptorBE32` / `DecryptorBE32` supplies the counter and final flag.
The full header is AAD on every segment. Header is followed by segments of
`chunk_size+16` bytes, except the final segment which contains remaining data
and a 16-byte tag. Empty plaintext uses one final empty segment with a tag.
The count is `max(1, ceil(plaintext_len/chunk_size))`. Exact encoded length is
checked before decryption. No plaintext is released until every segment passes.
Per-stream derivation avoids relying solely on the short random STREAM prefix
for AES-GCM or ChaCha20-Poly1305 when the input key is reused.

Sources: [RustCrypto aead 0.5.2 source](https://docs.rs/aead/0.5.2/src/aead/stream.rs.html),
[STREAM construction](https://eprint.iacr.org/2015/189).

## Hybrid KEM

Suite IDs: ML-KEM-512+X25519=0, 768+X25519=1, 1024+X25519=2.
`mlkem_ciphertext` exposed to callers is `2:u8 || raw_mlkem_ciphertext`.
X25519 ephemeral public key is a separate 32-byte field. Non-contributory
X25519 shared secrets fail in both directions. Decapsulation requires explicit
recipient public keys; both public components must match their secret keys.
ML-KEM public coefficients and the stored secret-key hash are validated before use.

`IKM = mlkem_shared_secret || x25519_shared_secret`.
HKDF-SHA256 salt is `"Quantum-Crypto/Hybrid-KEM/v2/extract"`.
Info is `"Quantum-Crypto/Hybrid-KEM/v2" || suite:u8 || field(recipient_mlkem_pk)
|| field(recipient_x25519_pk) || field(raw_mlkem_ct) || field(ephemeral_x25519_pk)`.
Output is 32 bytes. Altered ciphertext may yield a
different shared secret rather than an immediate error; key confirmation is
provided by a higher-layer authenticated operation, not by raw KEM output.

This adds context binding to the existing HKDF composition. It is not an
implementation of an IETF hybrid KEM specification and has no claimed security
proof. No forward secrecy under long-term recipient-key compromise is claimed.
See [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) and
[HKDF, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

## Message protection

Both DTOs include explicit `version=2`, ML-KEM ciphertext, X25519 ephemeral
public key, encrypted payload and suite enums. Encrypt-then-Sign also includes
a signature. Public keys and application AAD are supplied by callers and must
match at both ends. Their authenticity is an application responsibility.

DSA IDs: ML-DSA-44=0, 65=1, 87=2. KEM/AEAD IDs are those above. Composition
IDs: Sign-then-Encrypt=0, Encrypt-then-Sign=1.

Canonical context is `"Quantum-Crypto/Message/v2" || 2:u8 || mode:u8 || dsa:u8
|| kem:u8 || aead:u8 || field(sender_dsa_pk) || field(recipient_mlkem_pk)
|| field(recipient_x25519_pk) || field(versioned_mlkem_ct)
|| field(ephemeral_x25519_pk) || field(application_aad)`.
Let `C = SHA256(canonical_context)`.

The signed input is `SHA256("Quantum-Crypto/Message/v2/signature" || C
|| body_length:u64 || body)`. This application transcript hashing is not
HashML-DSA. The existing attached ML-DSA API signs the 32-byte digest.

- Sign-then-Encrypt: `body=message`; plaintext payload is
  `message_length:u32 || message || attached_signature`. Encrypt using the hybrid
  shared secret, the selected AEAD and AAD `C`.
- Encrypt-then-Sign: encrypt message using the shared secret and AAD `C`;
  `body=full_encrypted_payload` including nonce and tag. Verify the signature
  before decapsulation/decryption.

Signing checks that the supplied sender public key verifies the signature.
Native message operations get the sender/recipient public keys from their
handles. The authenticated context binds public keys, not real-world identities.
Packages have no replay database, sequence enforcement, ratchet or session state.
