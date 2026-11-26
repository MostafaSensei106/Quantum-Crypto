// NIST CAVS 14.0 gcmEncryptExtIV256.rsp, Count=0 in each indicated section.
// Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
use quantum_crypto::{
    api::key_serialization_api::hex_to_bytes,
    core::aead::{AeadAlgorithmVariant, AeadEngine},
};
#[test]
fn nist_gcm_256_known_answers() {
    // PTlen=0, AADlen=0, IVlen=96, Taglen=128
    {
        let key =
            hex_to_bytes("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4".into())
                .unwrap();
        let wire = hex_to_bytes("516c33929df5a3284ff463d7bdc1ac884d332457a1d2664f168c76f0".into())
            .unwrap();
        let aad = hex_to_bytes("".into()).unwrap();
        let expected = hex_to_bytes("".into()).unwrap();
        assert_eq!(
            AeadEngine::new(AeadAlgorithmVariant::Aes256Gcm)
                .decrypt_with_aad(&key, &wire, &aad)
                .unwrap(),
            expected
        );
    }
    // PTlen=0, AADlen=128, IVlen=96, Taglen=128
    {
        let key =
            hex_to_bytes("78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223".into())
                .unwrap();
        let wire = hex_to_bytes("d79cf22d504cc793c3fb6c8a3e5d486aa2e30b22e040b85723a06e76".into())
            .unwrap();
        let aad = hex_to_bytes("b96baa8c1c75a671bfb2d08d06be5f36".into()).unwrap();
        let expected = hex_to_bytes("".into()).unwrap();
        assert_eq!(
            AeadEngine::new(AeadAlgorithmVariant::Aes256Gcm)
                .decrypt_with_aad(&key, &wire, &aad)
                .unwrap(),
            expected
        );
    }
    // PTlen=128, AADlen=0, IVlen=96, Taglen=128
    {
        let key =
            hex_to_bytes("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22".into())
                .unwrap();
        let wire=hex_to_bytes("0d18e06c7c725ac9e362e1cefa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489".into()).unwrap();
        let aad = hex_to_bytes("".into()).unwrap();
        let expected = hex_to_bytes("2db5168e932556f8089a0622981d017d".into()).unwrap();
        assert_eq!(
            AeadEngine::new(AeadAlgorithmVariant::Aes256Gcm)
                .decrypt_with_aad(&key, &wire, &aad)
                .unwrap(),
            expected
        );
    }
    // PTlen=128, AADlen=128, IVlen=96, Taglen=128
    {
        let key =
            hex_to_bytes("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b".into())
                .unwrap();
        let wire=hex_to_bytes("ac93a1a6145299bde902f21a8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab".into()).unwrap();
        let aad = hex_to_bytes("1e0889016f67601c8ebea4943bc23ad6".into()).unwrap();
        let expected = hex_to_bytes("2d71bcfa914e4ac045b2aa60955fad24".into()).unwrap();
        assert_eq!(
            AeadEngine::new(AeadAlgorithmVariant::Aes256Gcm)
                .decrypt_with_aad(&key, &wire, &aad)
                .unwrap(),
            expected
        );
    }
}

// NIST ACVP-Server, gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json.
#[test]
fn nist_mlkem_acvp_sample() {
    use quantum_crypto::{api::kem_api::*, core::mlkem_validation::*};
    for line in include_str!("vectors/mlkem-acvp.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let f: Vec<_> = line.split('|').collect();
        let (algorithm, k) = match f[1] {
            "ML-KEM-512" => (TargetKemAlgorithm::MlKem512, 2),
            "ML-KEM-768" => (TargetKemAlgorithm::MlKem768, 3),
            _ => (TargetKemAlgorithm::MlKem1024, 4),
        };
        let decode = |s: &str| hex_to_bytes(s.into()).unwrap();
        match f[0] {
            "encapsulation" | "decapsulation" => assert_eq!(
                kem_decapsulate(algorithm, decode(f[6]), decode(f[5])).unwrap(),
                decode(f[7]),
                "tcId={}",
                f[2]
            ),
            "encapsulationKeyCheck" => assert_eq!(
                validate_public_key(&decode(f[4]), k).is_ok(),
                f[3] == "True",
                "tcId={}",
                f[2]
            ),
            "decapsulationKeyCheck" => assert_eq!(
                validate_secret_key(&decode(f[5]), k).is_ok(),
                f[3] == "True",
                "tcId={}",
                f[2]
            ),
            _ => panic!("Unknown vector function"),
        }
    }
}

#[test]
fn wycheproof_mldsa_verification_subset() {
    use quantum_crypto::api::dsa_api::*;
    for line in include_str!("vectors/mldsa-wycheproof.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let f: Vec<_> = line.split('|').collect();
        let algorithm = match f[0] {
            "44" => TargetDsaAlgorithm::MlDsa44,
            "65" => TargetDsaAlgorithm::MlDsa65,
            _ => TargetDsaAlgorithm::MlDsa87,
        };
        let decode = |s: &str| hex_to_bytes(s.into()).unwrap();
        let message = decode(f[4]);
        let mut attached = decode(f[5]);
        attached.extend_from_slice(&message);
        let accepted = dsa_verify(algorithm, message, attached, decode(f[3])).unwrap_or(false);
        assert_eq!(accepted, f[2] == "valid", "suite={} tcId={}", f[0], f[1]);
    }
}
