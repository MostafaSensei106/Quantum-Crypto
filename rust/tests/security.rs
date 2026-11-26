use quantum_crypto::{
    api::{aead_api::*, dsa_api::*, hybrid_kem_api::*, kdf_api::*, native_keys_api::*},
    core::{hybrid_kem::*, security::*},
};

#[test]
fn native_dsa_and_lifecycle() {
    for algorithm in [
        NativeKeyAlgorithm::MlDsa44,
        NativeKeyAlgorithm::MlDsa65,
        NativeKeyAlgorithm::MlDsa87,
    ] {
        let key = generate_native_key(algorithm, false, None).unwrap();
        let msg = b"native signing".to_vec();
        let sig = key.sign(msg.clone()).unwrap();
        let pk = key.public_key().unwrap();
        let target = match algorithm {
            NativeKeyAlgorithm::MlDsa44 => TargetDsaAlgorithm::MlDsa44,
            NativeKeyAlgorithm::MlDsa65 => TargetDsaAlgorithm::MlDsa65,
            _ => TargetDsaAlgorithm::MlDsa87,
        };
        assert!(dsa_verify(target, msg, sig, pk).unwrap());
        assert!(key.export_secret().is_err());
        assert!(key.encrypt(vec![], vec![]).is_err());
        let alias = key.clone();
        key.close().unwrap();
        key.close().unwrap();
        assert!(alias.sign(vec![]).is_err());
        assert!(alias.public_key().is_err());
    }
}
#[test]
fn policy_export_import_and_derivation() {
    assert!(generate_native_key(
        NativeKeyAlgorithm::MlDsa65,
        false,
        Some(vec![NativeKeyUsage::Decrypt])
    )
    .is_err());
    let key = generate_native_key(NativeKeyAlgorithm::MlDsa65, true, None).unwrap();
    let exported = key.export_secret().unwrap();
    let imported = import_native_key(
        NativeKeyAlgorithm::MlDsa65,
        exported.secret_key,
        vec![],
        key.public_key().unwrap(),
        vec![],
        false,
        None,
    )
    .unwrap();
    assert!(imported.sign(vec![]).is_ok());
    assert!(imported.export_secret().is_err());
    let seed = generate_native_key(NativeKeyAlgorithm::Seed, false, None).unwrap();
    assert!(seed
        .derive_aead(TargetNativeAead::Aes256Gcm, b"context".to_vec(), 0, true)
        .is_err());
    assert!(seed
        .derive_aead(TargetNativeAead::Aes256Gcm, vec![], 0, false)
        .is_err());
    let a = seed
        .derive_aead(
            TargetNativeAead::XChaCha20Poly1305,
            b"app".to_vec(),
            0,
            false,
        )
        .unwrap();
    let b = seed
        .derive_aead(
            TargetNativeAead::XChaCha20Poly1305,
            b"app".to_vec(),
            0,
            false,
        )
        .unwrap();
    let c = seed
        .derive_aead(
            TargetNativeAead::XChaCha20Poly1305,
            b"other".to_vec(),
            0,
            false,
        )
        .unwrap();
    let ct = a.encrypt(b"secret".to_vec(), b"metadata".to_vec()).unwrap();
    assert_eq!(
        b.decrypt(ct.clone(), b"metadata".to_vec()).unwrap(),
        b"secret"
    );
    assert!(b.decrypt(ct.clone(), vec![]).is_err());
    assert!(c.decrypt(ct, b"metadata".to_vec()).is_err());
    for chunk in [1, 64, 65536] {
        let ct = a.stream_encrypt(vec![1; 256], Some(chunk)).unwrap();
        assert_eq!(b.stream_decrypt(ct).unwrap(), vec![1; 256]);
    }
    let only_encrypt = generate_native_key(
        NativeKeyAlgorithm::Aes256Gcm,
        false,
        Some(vec![NativeKeyUsage::Encrypt]),
    )
    .unwrap();
    assert!(only_encrypt.decrypt(vec![], vec![]).is_err());
}
#[test]
fn concurrent_use_and_close() {
    let key = generate_native_key(NativeKeyAlgorithm::MlDsa44, false, None).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut threads = vec![];
    for _ in 0..2 {
        let k = key.clone();
        let b = barrier.clone();
        threads.push(std::thread::spawn(move || {
            b.wait();
            for _ in 0..10 {
                let _ = k.sign(b"message".to_vec());
            }
        }));
    }
    barrier.wait();
    key.close().unwrap();
    for t in threads {
        t.join().unwrap();
    }
    assert!(key.sign(vec![]).is_err());
}
#[test]
fn native_kem_secrets_stay_native() {
    for algorithm in [
        NativeKeyAlgorithm::MlKem512,
        NativeKeyAlgorithm::MlKem768,
        NativeKeyAlgorithm::MlKem1024,
        NativeKeyAlgorithm::MlKem512X25519,
        NativeKeyAlgorithm::MlKem768X25519,
        NativeKeyAlgorithm::MlKem1024X25519,
    ] {
        let key = generate_native_key(algorithm, false, None).unwrap();
        let e = native_encapsulate(
            algorithm,
            key.public_key().unwrap(),
            key.secondary_public_key().unwrap(),
            false,
        )
        .unwrap();
        let recovered = key
            .decapsulate(e.ciphertext, e.x25519_ephemeral_pk)
            .unwrap();
        assert!(e.shared_secret.export_secret().is_err());
        assert!(recovered.export_secret().is_err());
        let a = e
            .shared_secret
            .derive_aead(TargetNativeAead::Aes256Gcm, b"session".to_vec(), 0, false)
            .unwrap();
        let b = recovered
            .derive_aead(TargetNativeAead::Aes256Gcm, b"session".to_vec(), 0, false)
            .unwrap();
        let ct = a.encrypt(b"roundtrip".to_vec(), vec![]).unwrap();
        assert_eq!(b.decrypt(ct, vec![]).unwrap(), b"roundtrip");
    }
}
#[test]
fn hybrid_v2_validation_and_binding() {
    for variant in [
        HybridKemVariant::MlKem512X25519,
        HybridKemVariant::MlKem768X25519,
        HybridKemVariant::MlKem1024X25519,
    ] {
        let engine = HybridKemEngine::new(variant);
        let p = engine.generate_keypair().unwrap();
        for low in [vec![0; 32], {
            let mut v = vec![0; 32];
            v[0] = 1;
            v
        }] {
            assert!(engine.encapsulate(&p.mlkem_public_key, &low).is_err());
        }
        let e = engine
            .encapsulate(&p.mlkem_public_key, &p.x25519_public_key)
            .unwrap();
        let dec = |ct: &[u8], ep: &[u8], pk: &[u8]| {
            engine.decapsulate(
                ct,
                ep,
                &p.mlkem_secret_key,
                &p.x25519_secret_key,
                pk,
                &p.x25519_public_key,
            )
        };
        assert_eq!(
            dec(
                &e.mlkem_ciphertext,
                &e.x25519_ephemeral_pk,
                &p.mlkem_public_key
            )
            .unwrap(),
            e.shared_secret
        );
        assert!(dec(&e.mlkem_ciphertext, &[0; 32], &p.mlkem_public_key).is_err());
        let mut pk = p.mlkem_public_key.clone();
        pk[0] ^= 1;
        assert!(dec(&e.mlkem_ciphertext, &e.x25519_ephemeral_pk, &pk).is_err());
        let mut old = e.mlkem_ciphertext.clone();
        old[0] = 1;
        assert!(dec(&old, &e.x25519_ephemeral_pk, &p.mlkem_public_key).is_err());
    }
}
#[test]
fn message_v2_modes_and_context() {
    let sender = generate_native_key(NativeKeyAlgorithm::MlDsa65, false, None).unwrap();
    let recipient = generate_native_key(NativeKeyAlgorithm::MlKem768X25519, false, None).unwrap();
    for aead in [
        TargetAeadAlgorithm::Aes256Gcm,
        TargetAeadAlgorithm::ChaCha20Poly1305,
        TargetAeadAlgorithm::XChaCha20Poly1305,
    ] {
        for msg in [vec![], b"message".to_vec()] {
            let make = || {
                sender
                    .sign_and_encrypt(
                        msg.clone(),
                        TargetHybridKemAlgorithm::MlKem768X25519,
                        recipient.public_key().unwrap(),
                        recipient.secondary_public_key().unwrap(),
                        aead,
                        b"app".to_vec(),
                    )
                    .unwrap()
            };
            let p = make();
            assert_eq!(
                recipient
                    .decrypt_and_verify(p, sender.public_key().unwrap(), b"app".to_vec())
                    .unwrap(),
                msg
            );
            assert!(recipient
                .decrypt_and_verify(make(), sender.public_key().unwrap(), b"other".to_vec())
                .is_err());
            for field in 0..7 {
                let mut p = make();
                match field {
                    0 => p.version = 1,
                    1 => p.mlkem_ciphertext[3] ^= 1,
                    2 => p.x25519_ephemeral_pk[0] ^= 1,
                    3 => p.encrypted_payload[0] ^= 1,
                    4 => p.dsa_algorithm = TargetDsaAlgorithm::MlDsa44,
                    5 => p.kem_algorithm = TargetHybridKemAlgorithm::MlKem512X25519,
                    _ => {
                        p.aead_algorithm = if aead == TargetAeadAlgorithm::Aes256Gcm {
                            TargetAeadAlgorithm::XChaCha20Poly1305
                        } else {
                            TargetAeadAlgorithm::Aes256Gcm
                        }
                    }
                };
                assert!(recipient
                    .decrypt_and_verify(p, sender.public_key().unwrap(), b"app".to_vec())
                    .is_err());
            }
            let make = || {
                sender
                    .encrypt_and_sign(
                        msg.clone(),
                        TargetHybridKemAlgorithm::MlKem768X25519,
                        recipient.public_key().unwrap(),
                        recipient.secondary_public_key().unwrap(),
                        aead,
                        b"app".to_vec(),
                    )
                    .unwrap()
            };
            assert_eq!(
                recipient
                    .verify_and_decrypt(make(), sender.public_key().unwrap(), b"app".to_vec())
                    .unwrap(),
                msg
            );
            for field in 0..5 {
                let mut p = make();
                match field {
                    0 => p.version = 1,
                    1 => p.mlkem_ciphertext[3] ^= 1,
                    2 => p.x25519_ephemeral_pk[0] ^= 1,
                    3 => p.encrypted_payload[0] ^= 1,
                    _ => p.signature[0] ^= 1,
                };
                assert!(recipient
                    .verify_and_decrypt(p, sender.public_key().unwrap(), b"app".to_vec())
                    .is_err());
            }
        }
    }
}
#[test]
fn rfc5869_case1() {
    let out = hkdf_derive_with_hash(
        vec![0x0b; 22],
        (0..=12).collect(),
        (0xf0..=0xf9).collect(),
        42,
        TargetHkdfHash::Sha256,
    )
    .unwrap();
    assert_eq!(
        quantum_crypto::api::key_serialization_api::bytes_to_hex(out),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}
#[test]
fn malformed_hex_and_size_bounds() {
    for text in ["a€", "💣", "é00", "0xgg"] {
        assert!(quantum_crypto::api::key_serialization_api::hex_to_bytes(text.into()).is_err());
    }
    assert!(bounded(usize::MAX, MAX_PLAINTEXT).is_err());
    let mut out = vec![];
    append_field(&mut out, b"ab").unwrap();
    assert_eq!(out, vec![0, 0, 0, 2, b'a', b'b']);
}

proptest::proptest! {
 #[test]
 fn streaming_property(data in proptest::collection::vec(proptest::prelude::any::<u8>(),0..8192), chunk in 1usize..2048, variant in 0u8..3) {
  use quantum_crypto::core::{aead::AeadAlgorithmVariant as V,streaming::*};
  let v=match variant {0=>V::Aes256Gcm,1=>V::ChaCha20Poly1305,_=>V::XChaCha20Poly1305};
  let encrypted=stream_encrypt(&[0x59;32],&data,v,Some(chunk)).unwrap();
  proptest::prop_assert_eq!(stream_decrypt(&[0x59;32],&encrypted).unwrap(),data);
  let mut bad=encrypted.clone();let end=bad.len()-1;bad[end]^=1;
  proptest::prop_assert!(stream_decrypt(&[0x59;32],&bad).is_err());
 }
 #[test]
 fn parser_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(),0..2048)) {
  let _=quantum_crypto::core::streaming::stream_decrypt(&[0;32],&data);
  if let Ok(text)=String::from_utf8(data){let _=quantum_crypto::api::key_serialization_api::hex_to_bytes(text);}
 }
}

#[cfg(target_os = "linux")]
#[test]
fn independent_openssl_interoperability() {
    use quantum_crypto::{
        api::key_serialization_api::bytes_to_hex as hex,
        core::{
            aead::{AeadAlgorithmVariant as V, AeadEngine},
            streaming::*,
        },
    };
    for (id, variant) in [(0, V::Aes256Gcm), (1, V::ChaCha20Poly1305)] {
        for message in [vec![], vec![0x21; 257]] {
            let key = vec![0x6b; 32];
            let aad = b"application-context".to_vec();
            for stream in [false, true] {
                let ct = if stream {
                    stream_encrypt(&key, &message, variant, Some(64)).unwrap()
                } else {
                    AeadEngine::new(variant)
                        .encrypt_with_aad(&key, &message, &aad)
                        .unwrap()
                };
                let output = std::process::Command::new("python3")
                    .arg(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../tools/openssl_interop.py"
                    ))
                    .args([
                        if stream { "stream" } else { "aead" },
                        &id.to_string(),
                        &hex(key.clone()),
                        &hex(ct),
                        &hex(aad.clone()),
                        &hex(message.clone()),
                    ])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[test]
fn mlkem_input_checks_all_parameter_sets() {
    use quantum_crypto::{api::kem_api::*, core::mlkem_validation::*};
    for (algorithm, k) in [
        (TargetKemAlgorithm::MlKem512, 2),
        (TargetKemAlgorithm::MlKem768, 3),
        (TargetKemAlgorithm::MlKem1024, 4),
    ] {
        let pair = generate_kem_keypair(algorithm).unwrap();
        assert_eq!(
            validate_secret_key(&pair.secret_key, k).unwrap(),
            pair.public_key
        );
        let mut bad_pk = pair.public_key.clone();
        bad_pk[0] = 0xff;
        bad_pk[1] |= 0x0f;
        assert!(kem_encapsulate(algorithm, bad_pk).is_err());
        let ct = kem_encapsulate(algorithm, pair.public_key.clone())
            .unwrap()
            .ciphertext;
        for index in [384 * k, 768 * k + 32] {
            let mut sk = pair.secret_key.clone();
            sk[index] ^= 1;
            assert!(kem_decapsulate(algorithm, ct.clone(), sk).is_err());
        }
    }
}
