/// The test vectors come from https://eips.ethereum.org/EIPS/eip-2335.
/// The password and secret for the test vectors are as follows:
/// Password "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑" Encoded Password: 0x7465737470617373776f7264f09f9491 Secret 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
#[cfg(test)]
mod tests {

    use rand::RngCore;
    use std::str::FromStr;
    use uuid::Uuid;

    use bls_keystore::{
        aes_128_cipher::{Aes128CtrCipher, Aes128CtrCipherParams},
        derivation_path::DerivationPath,
        key_derivation::KeyDerivationFunction,
        keystore::{DecryptError, KeyStore, KeyStoreCrypto},
        pbkdf::{Pbkdf2Kdf, Pbkdf2KdfParamsBuilder, PseudoRandomFunction},
        scrypt::{ScryptKdf, ScryptKdfParamsBuilder},
        sha256_checksum::{Sha2Checksum, Sha2ChecksumParams},
    };

    // Test password from the vectors (Unicode password encoded as UTF-8)
    const ENCODED_PASSWORD: &[u8] = &[
        0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f, 0x94,
        0x91,
    ];

    // Expected secret key that should be decrypted from both vectors
    const EXPECTED_SECRET_KEY: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    // Helper function to create a keystore from test vector components
    #[allow(clippy::too_many_arguments)]
    fn create_test_keystore<KDF>(
        kdf: KDF,
        iv: [u8; 16],
        cipher_message: Vec<u8>,
        checksum_message: Vec<u8>,
        pubkey: Vec<u8>,
        path: DerivationPath,
        uuid: Uuid,
        description: Option<String>,
    ) -> KeyStore<KDF>
    where
        KDF: KeyDerivationFunction,
    {
        let crypto = KeyStoreCrypto {
            kdf,
            checksum: Sha2Checksum {
                message: checksum_message,
                params: Sha2ChecksumParams {},
            },
            cipher: Aes128CtrCipher {
                params: Aes128CtrCipherParams { iv },
                message: cipher_message,
            },
        };

        KeyStore {
            version: 4,
            uuid,
            description,
            path,
            pubkey,
            crypto,
        }
    }

    #[test]
    fn test_roundtrip_with_pbkdf2_test_vector_params() {
        // Use exact parameters from PBKDF2 test vector
        let pbkdf2_json = include_str!("pbkdf2_vector.json");
        let pbkdf2_data: serde_json::Value = serde_json::from_str(pbkdf2_json).unwrap();

        let secret_key = hex::decode(EXPECTED_SECRET_KEY).unwrap();
        let salt = hex::decode(
            pbkdf2_data["crypto"]["kdf"]["params"]["salt"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let c = pbkdf2_data["crypto"]["kdf"]["params"]["c"]
            .as_u64()
            .unwrap() as u32;
        let iv = hex::decode(
            pbkdf2_data["crypto"]["cipher"]["params"]["iv"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let path = DerivationPath::from_str(pbkdf2_data["path"].as_str().unwrap()).unwrap();

        // Create PBKDF2 KDF with test vector parameters
        let pbkdf2_params = Pbkdf2KdfParamsBuilder {
            c,
            salt,
            prf: PseudoRandomFunction::Sha256,
        };
        let kdf = Pbkdf2Kdf::try_from(pbkdf2_params).unwrap();

        // Encrypt with exact IV from test vector
        let keystore = KeyStore::encrypt(
            &secret_key,
            ENCODED_PASSWORD,
            path,
            Some("Test roundtrip with PBKDF2 vector params".to_string()),
            Some(iv),
            kdf,
        )
        .unwrap();

        // Decrypt and verify
        let decrypted_key = keystore.decrypt(ENCODED_PASSWORD).unwrap();
        assert_eq!(
            decrypted_key.to_vec(),
            secret_key,
            "PBKDF2 test vector roundtrip failed"
        );

        // Verify the encrypted result matches expected cipher text from test vector
        let expected_cipher =
            hex::decode(pbkdf2_data["crypto"]["cipher"]["message"].as_str().unwrap()).unwrap();
        assert_eq!(
            keystore.crypto.cipher.message, expected_cipher,
            "PBKDF2 cipher text should match test vector"
        );

        // Verify checksum matches test vector
        let expected_checksum = hex::decode(
            pbkdf2_data["crypto"]["checksum"]["message"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            keystore.crypto.checksum.message, expected_checksum,
            "PBKDF2 checksum should match test vector"
        );
    }

    #[test]
    fn test_roundtrip_with_scrypt_test_vector_params() {
        // Use exact parameters from Scrypt test vector
        let scrypt_json = include_str!("scrypt_vector.json");
        let scrypt_data: serde_json::Value = serde_json::from_str(scrypt_json).unwrap();

        let secret_key = hex::decode(EXPECTED_SECRET_KEY).unwrap();
        let salt = hex::decode(
            scrypt_data["crypto"]["kdf"]["params"]["salt"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let n = scrypt_data["crypto"]["kdf"]["params"]["n"]
            .as_u64()
            .unwrap() as u32;
        let r = scrypt_data["crypto"]["kdf"]["params"]["r"]
            .as_u64()
            .unwrap() as u32;
        let p = scrypt_data["crypto"]["kdf"]["params"]["p"]
            .as_u64()
            .unwrap() as u32;
        let iv = hex::decode(
            scrypt_data["crypto"]["cipher"]["params"]["iv"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let path = DerivationPath::from_str(scrypt_data["path"].as_str().unwrap()).unwrap();

        // Create Scrypt KDF with test vector parameters
        let scrypt_params = ScryptKdfParamsBuilder { n, r, p, salt };
        let kdf = ScryptKdf::try_from(scrypt_params).unwrap();

        // Encrypt with exact IV from test vector
        let keystore = KeyStore::encrypt(
            &secret_key,
            ENCODED_PASSWORD,
            path,
            Some("Test roundtrip with Scrypt vector params".to_string()),
            Some(iv),
            kdf,
        )
        .unwrap();

        // Decrypt and verify
        let decrypted_key = keystore.decrypt(ENCODED_PASSWORD).unwrap();
        assert_eq!(
            decrypted_key.to_vec(),
            secret_key,
            "Scrypt test vector roundtrip failed"
        );

        // Verify the encrypted result matches expected cipher text from test vector
        let expected_cipher =
            hex::decode(scrypt_data["crypto"]["cipher"]["message"].as_str().unwrap()).unwrap();
        assert_eq!(
            keystore.crypto.cipher.message, expected_cipher,
            "Scrypt cipher text should match test vector"
        );

        // Verify checksum matches test vector
        let expected_checksum = hex::decode(
            scrypt_data["crypto"]["checksum"]["message"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            keystore.crypto.checksum.message, expected_checksum,
            "Scrypt checksum should match test vector"
        );
    }

    #[test]
    fn test_roundtrip_different_params_pbkdf2() {
        // Use a different secret key and password to test parameter variation
        let mut rng = rand::rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let secret_key = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .to_bytes();
        let path = DerivationPath::from_str("m/12381/3600/1/0").unwrap();

        // Different password: "mypassword123" encoded as UTF-8
        let different_password = b"mypassword123";

        // Create PBKDF2 KDF with different parameters
        let pbkdf2_params = Pbkdf2KdfParamsBuilder {
            c: 2_u32.pow(18) + 12345, // Different iteration count
            salt: hex::decode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
                .unwrap(),
            prf: PseudoRandomFunction::Sha256,
        };
        let kdf = Pbkdf2Kdf::try_from(pbkdf2_params).unwrap();

        // Encrypt with different IV
        let keystore = KeyStore::encrypt(
            &secret_key,
            different_password,
            path,
            Some("Test keystore with different params".to_string()),
            Some(hex::decode("fedcba0987654321fedcba0987654321").unwrap()),
            kdf,
        )
        .unwrap();

        // Decrypt and verify
        let decrypted_key = keystore.decrypt(different_password).unwrap();
        assert_eq!(
            decrypted_key.to_vec(),
            secret_key,
            "PBKDF2 encrypt/decrypt roundtrip failed"
        );
    }

    #[test]
    fn test_roundtrip_different_params_scrypt() {
        // Use a different secret key and password to test parameter variation
        let mut rng = rand::rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let secret_key = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .to_bytes();
        let path = DerivationPath::from_str("m/12381/3600/2/0/1").unwrap();

        // Different password: "securepass456" encoded as UTF-8
        let different_password = b"securepass456";

        // Create Scrypt KDF with different parameters
        let scrypt_params = ScryptKdfParamsBuilder {
            n: 2_u32.pow(18), // Different N value
            r: 8,             // Different r value
            p: 1,             // Different p value
            salt: hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
        };
        let kdf = ScryptKdf::try_from(scrypt_params).unwrap();

        // Encrypt with different IV
        let keystore = KeyStore::encrypt(
            &secret_key,
            different_password,
            path,
            Some("Test keystore with different scrypt params".to_string()),
            Some(hex::decode("0123456789abcdef0123456789abcdef").unwrap()),
            kdf,
        )
        .unwrap();

        // Decrypt and verify
        let decrypted_key = keystore.decrypt(different_password).unwrap();
        assert_eq!(
            decrypted_key.to_vec(),
            secret_key,
            "Scrypt encrypt/decrypt roundtrip failed"
        );
    }

    #[test]
    fn test_wrong_password_pbkdf2() {
        let pbkdf2_json = include_str!("pbkdf2_vector.json");
        let pbkdf2_data: serde_json::Value = serde_json::from_str(pbkdf2_json).unwrap();

        let salt = hex::decode(
            pbkdf2_data["crypto"]["kdf"]["params"]["salt"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let c = pbkdf2_data["crypto"]["kdf"]["params"]["c"]
            .as_u64()
            .unwrap() as u32;
        let iv = hex::decode(
            pbkdf2_data["crypto"]["cipher"]["params"]["iv"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let cipher_message =
            hex::decode(pbkdf2_data["crypto"]["cipher"]["message"].as_str().unwrap()).unwrap();
        let checksum_message = hex::decode(
            pbkdf2_data["crypto"]["checksum"]["message"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let pubkey = hex::decode(pbkdf2_data["pubkey"].as_str().unwrap()).unwrap();
        let path = DerivationPath::from_str(pbkdf2_data["path"].as_str().unwrap()).unwrap();
        let uuid = Uuid::from_str(pbkdf2_data["uuid"].as_str().unwrap()).unwrap();

        let pbkdf2_params = Pbkdf2KdfParamsBuilder {
            c,
            salt,
            prf: PseudoRandomFunction::Sha256,
        };
        let kdf = Pbkdf2Kdf::try_from(pbkdf2_params).unwrap();

        let keystore = create_test_keystore(
            kdf,
            iv.try_into().unwrap(),
            cipher_message,
            checksum_message,
            pubkey,
            path,
            uuid,
            None,
        );

        // Test with wrong password
        let result = keystore.decrypt(b"wrongpassword");
        assert!(
            matches!(result, Err(DecryptError::ChecksumMismatch)),
            "PBKDF2 should fail with wrong password"
        );
    }

    #[test]
    fn test_wrong_password_scrypt() {
        let scrypt_json = include_str!("scrypt_vector.json");
        let scrypt_data: serde_json::Value = serde_json::from_str(scrypt_json).unwrap();

        let salt = hex::decode(
            scrypt_data["crypto"]["kdf"]["params"]["salt"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let n = scrypt_data["crypto"]["kdf"]["params"]["n"]
            .as_u64()
            .unwrap() as u32;
        let r = scrypt_data["crypto"]["kdf"]["params"]["r"]
            .as_u64()
            .unwrap() as u32;
        let p = scrypt_data["crypto"]["kdf"]["params"]["p"]
            .as_u64()
            .unwrap() as u32;
        let iv = hex::decode(
            scrypt_data["crypto"]["cipher"]["params"]["iv"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let cipher_message =
            hex::decode(scrypt_data["crypto"]["cipher"]["message"].as_str().unwrap()).unwrap();
        let checksum_message = hex::decode(
            scrypt_data["crypto"]["checksum"]["message"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let pubkey = hex::decode(scrypt_data["pubkey"].as_str().unwrap()).unwrap();
        let path = DerivationPath::from_str(scrypt_data["path"].as_str().unwrap()).unwrap();
        let uuid = Uuid::from_str(scrypt_data["uuid"].as_str().unwrap()).unwrap();

        let scrypt_params = ScryptKdfParamsBuilder { n, r, p, salt };
        let kdf = ScryptKdf::try_from(scrypt_params).unwrap();

        let keystore = create_test_keystore(
            kdf,
            iv.try_into().unwrap(),
            cipher_message,
            checksum_message,
            pubkey,
            path,
            uuid,
            None,
        );

        // Test with wrong password
        let result = keystore.decrypt(b"wrongpassword");
        assert!(
            matches!(result, Err(DecryptError::ChecksumMismatch)),
            "Scrypt should fail with wrong password"
        );
    }
}
