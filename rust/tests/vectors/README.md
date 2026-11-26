# Vector provenance

`mlkem-acvp.txt` is a selected, reformatted subset of the NIST ACVP sample
ML-KEM encapDecap FIPS203 internalProjection.json (vsId 42), fetched 2026-11-26.
It contains 12 decapsulation known-answer cases and 60 public/secret key check
cases, with original tcIds. It does not test deterministic encapsulation or
key generation because the exposed backend uses its own RNG.
Source: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json

`mldsa-wycheproof.txt` contains 57 selected empty-context verification cases
across ML-DSA-44/65/87, retaining tcIds. It includes valid, norm-violation,
boundary and malformed-length cases. The detached reference signatures are
converted to the backend's attached representation by appending the message.
This is a subset, not the full Wycheproof suite. Source files:
https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
(`mldsa_44_verify_test.json`, `mldsa_65_verify_test.json`, `mldsa_87_verify_test.json`).
The derived fixture data remains under the upstream Apache-2.0 license,
reproduced in LICENSE.wycheproof. Original source SHA256 values are recorded
in fixture headers. Only selection/reformatting was performed.

The AES-GCM cases embedded in ../nist_vectors.rs come from NIST CAVS 14.0
`gcmEncryptExtIV256.rsp`, Count=0 in the four selected IVlen=96/Taglen=128
sections with PTlen/AADlen in {0,128}. Source:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

HKDF case 1 is from RFC 5869 Appendix A.1:
https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1

Passing these fixtures does not constitute NIST CAVP/FIPS validation.
