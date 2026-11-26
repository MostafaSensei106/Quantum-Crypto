# Threat model and security limits  0.0.3 Dev Preview

The library protects bytes using upstream cryptographic implementations and
project composition code. Attackers may modify, reorder, truncate, append or
replay ciphertext and metadata, supply malformed encodings, or choose invalid
public keys. The application is responsible for limiting ingress before FFI,
authenticating public keys, restricting request rates, and selecting contexts.

Expected protections tested here include AEAD/AAD integrity, full STREAM-v2
integrity including empty input and finalization, context binding in v2 message
protection, rejection of non-contributory X25519 keys, and native export/usage
and disposal policies. Randomness depends on the operating-system CSPRNG.

Hybrid composition and messaging have not received independent specialist
review. Tests do not prove protocol security, algorithm conformance, constant-time
execution of the complete library, or absence of vulnerabilities. This is not a
FIPS-validated cryptographic module. SPHINCS+ backend equivalence to final FIPS
205 SLH-DSA is unverified; API names alone do not establish that equivalence.

Excluded guarantees: forward secrecy with static recipients, identity verification,
replay prevention, sessions, post-compromise recovery, hardware-backed key storage,
protection from a compromised process/OS, side-channel immunity of all dependencies,
or protection against all future cryptanalysis. A quantum attacker capable of
breaking X25519 eliminates its classical contribution. Master-seed compromise
exposes all deterministically derived keys; HKDF cannot strengthen a low-entropy
password into a high-entropy master secret.

Native handles keep generated private bytes out of Dart and zeroize the buffers
owned by this project on close/drop. Upstream pqcrypto/C temporary keys and shared
secrets are not comprehensively erased by this change. Neither upstream HKDF
internal state nor stack/register spills, allocator copies, operating-system
paging, crash dumps or Dart import/export/legacy buffers have a universal erasure
guarantee. Read-only Dart snapshots prevent accidental mutation, not memory reads
or secure disposal. Retain secrets only as long as needed.

Bounds are checked by core operations: 64 MiB application plaintext, 1 MiB
application AAD, 1 MiB maximum chunk and 66 MiB maximum encoded stream. Core AEAD
allows up to 66 MiB plaintext internally to accommodate signed-message framing;
the public raw/native encryption APIs enforce 64 MiB. There are transient copies
and simultaneous buffers. FFI can allocate before validation; concurrent calls
can exceed aggregate memory even when each call fits. Native failures return
errors where handled; unwind improves bridge panic handling but cannot recover
from OOM aborts, process signals or upstream native crashes.

No persistent usage counter is implemented. For 96-bit random-nonce AEAD, this
project recommends at most 2^16 encryptions per key across all users/copies as a
conservative collision-risk policy (roughly 2^-65 nonce-collision probability).
This is not a complete per-cipher forgery/data-volume analysis. Rotate earlier
where required; prefer XChaCha20-Poly1305 for random-nonce applications. Failed
authentication attempts and message sizes also affect practical security budgets.
