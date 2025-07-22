//! PBKDF2 is Password-Based Key Derivation Function 2.
//! Its primary purpose in BLS12-381 Keystore Implementation (ERC-2335)
//! is turning a human-readable password into a strong cryptographic key
//! that can encrypt/decrypt the BLS private key.
//!
//! Its parameter `c` is for adjusting the number of iterations, i.e. the computational cost. The higher
//! `c` is, the more time an attacker needs to spend on each time he guesses
//! a password. Its minimum iteration is 2^18 for SHA-256 for security.
//!
//! `salt` prevents something called rainbow table attacks. It ensures that
//! identitcal passwords produce different encryption keys each time, similarly
//! to how `iv` works for AES-128.
//!
//! A rainbow table attack is a way that hackers use to crack passwords very fast
//! based on a pre-computed lookup tables. If the salt is the same for all passwords,
//! an attacker can create a dictionary of hashed passwords with a guessed salt, and
//! try to find a matching hash from the table against the provided hash.
//! Imagine if 10000 keystores are created using the same salt and different passwords.
//! Then every keystore is now more vulnerable to the rainbow attack.

use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2;
use thiserror::Error;

use crate::{
    key_derivation::{KeyDerivationError, KeyDerivationFunction},
    keystore::KdfLiteral,
};

#[derive(Debug, Clone)]
pub enum PseudoRandomFunction {
    Sha256,
    Sha512,
}

#[derive(Debug, Error)]
pub enum CreatePbkdf2ParamsError {
    #[error("The PBKDF2 parameters chosen are not secure: c must be >= 2^18, but got c={c}")]
    InsecureParameters { c: u32 },
}

/// PBKDF Key derivation function.
///
/// Derives a key from a password
#[derive(Debug, Clone)]
pub struct Pbkdf2 {
    params: Pbkdf2Params,
}

/// Serialization structure for PBKDF2 KDF parameters matching ERC-2335 format
#[derive(Serialize, Deserialize)]
struct Pbkdf2ParamsSerde {
    dklen: u8,
    c: u32,
    prf: PseudoRandomFunction,
    #[serde(with = "hex")]
    salt: Vec<u8>,
}

/// Serialization structure for the complete PBKDF2 KDF matching ERC-2335 format
#[derive(Serialize, Deserialize)]
struct Pbkdf2Serde {
    function: String,
    params: Pbkdf2ParamsSerde,
    message: String,
}

#[derive(Debug, Clone)]
pub struct Pbkdf2ParamsBuilder {
    pub c: u32,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    pub salt: Vec<u8>,
    /// Pseudo-random function to use
    pub prf: PseudoRandomFunction,
}

#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    /// Output of the derived key in bytes.
    ///
    /// For example, dklen = 32 means that the derived key will be 32 bytes long.
    ///
    /// For ERC-2335 keystores, dklen must be 32 bytes (16 for AES-128-CTR + 16 for checksum).
    pub dklen: u8,
    /// Number of iterations to use in the PBKDF2 algorithm
    pub c: u32,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    pub salt: Vec<u8>,
    /// Pseudo-random function to use
    pub prf: PseudoRandomFunction,
}

impl Pbkdf2 {
    fn new(params: Pbkdf2Params) -> Self {
        Self { params }
    }
}

impl Pbkdf2ParamsBuilder {
    pub fn new(c: u32, salt: Vec<u8>, prf: PseudoRandomFunction) -> Self {
        Self { c, salt, prf }
    }
}

impl KeyDerivationFunction for Pbkdf2 {
    /// Derives a 32-byte key from the given password and salt using PBKDF2.
    fn derive_key(&self, password: &[u8]) -> Result<[u8; 32], KeyDerivationError> {
        // The spec is not finalized, and currently dklen can only be 32 bytes.
        if self.params.dklen != 32 {
            return Err(KeyDerivationError::InvalidDklen {
                dklen: self.params.dklen,
            });
        }

        let mut output = [0u8; 32];

        match self.params.prf {
            PseudoRandomFunction::Sha256 => {
                pbkdf2_hmac::<sha2::Sha256>(
                    password,
                    &self.params.salt,
                    self.params.c,
                    &mut output,
                );
            }
            PseudoRandomFunction::Sha512 => {
                pbkdf2_hmac::<sha2::Sha512>(
                    password,
                    &self.params.salt,
                    self.params.c,
                    &mut output,
                );
            }
        }

        Ok(output)
    }

    fn kdf(&self) -> KdfLiteral {
        KdfLiteral::Pbkdf2
    }

    fn salt(&self) -> Vec<u8> {
        self.params.salt.clone()
    }
}

impl Serialize for PseudoRandomFunction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let prf_str = match self {
            PseudoRandomFunction::Sha256 => "hmac-sha256",
            PseudoRandomFunction::Sha512 => "hmac-sha512",
        };
        serializer.serialize_str(prf_str)
    }
}

impl<'de> Deserialize<'de> for PseudoRandomFunction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let prf_str = String::deserialize(deserializer)?;
        match prf_str.as_str() {
            "hmac-sha256" => Ok(PseudoRandomFunction::Sha256),
            "hmac-sha512" => Ok(PseudoRandomFunction::Sha512),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown PRF: {prf_str}. Expected 'hmac-sha256' or 'hmac-sha512'"
            ))),
        }
    }
}

impl Serialize for Pbkdf2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serde_struct = Pbkdf2Serde {
            function: "pbkdf2".to_string(),
            params: Pbkdf2ParamsSerde {
                dklen: self.params.dklen,
                c: self.params.c,
                prf: self.params.prf.clone(),
                salt: self.params.salt.clone(),
            },
            message: "".to_string(),
        };
        serde_struct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Pbkdf2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serde_struct = Pbkdf2Serde::deserialize(deserializer)?;

        // Validate that function is "pbkdf2"
        if serde_struct.function != "pbkdf2" {
            return Err(serde::de::Error::custom(format!(
                "Expected function 'pbkdf2', got '{}'",
                serde_struct.function
            )));
        }

        // Create Pbkdf2ParamsBuilder from deserialized data
        let builder = Pbkdf2ParamsBuilder {
            c: serde_struct.params.c,
            salt: serde_struct.params.salt,
            prf: serde_struct.params.prf,
        };

        // Convert to Pbkdf2 using existing validation
        Pbkdf2::try_from(builder).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl TryFrom<Pbkdf2ParamsBuilder> for Pbkdf2 {
    type Error = CreatePbkdf2ParamsError;

    /// Refer to https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/utils/crypto.py#L41C27-L41C71
    /// for parameter validation
    fn try_from(params: Pbkdf2ParamsBuilder) -> Result<Self, Self::Error> {
        if let PseudoRandomFunction::Sha256 = params.prf {
            if params.c < (2_u32.pow(18)) {
                return Err(CreatePbkdf2ParamsError::InsecureParameters { c: params.c });
            }
        }

        Ok(Self::new(Pbkdf2Params {
            dklen: 32, // 16 for AES, 16 for checksum
            c: params.c,
            salt: params.salt,
            prf: params.prf,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::pbkdf::{
        CreatePbkdf2ParamsError, Pbkdf2, Pbkdf2ParamsBuilder, PseudoRandomFunction,
    };

    #[test]
    fn test_insecure_parameters_sha256_below_threshold() {
        // Test case where c < 2^18 (262144) for SHA256
        let params = Pbkdf2ParamsBuilder {
            c: 262143, // Just below 2^18
            salt: vec![0u8; 32],
            prf: PseudoRandomFunction::Sha256,
        };

        let result = Pbkdf2::try_from(params);

        assert!(matches!(
            result,
            Err(CreatePbkdf2ParamsError::InsecureParameters { c: 262143 })
        ));
    }
    #[test]
    fn test_secure_parameters_sha256_at_threshold() {
        // Test parameters exactly at the security threshold for SHA256
        let params = Pbkdf2ParamsBuilder {
            c: 262144, // Exactly 2^18
            salt: vec![0u8; 32],
            prf: PseudoRandomFunction::Sha256,
        };

        let result = Pbkdf2::try_from(params);

        // This should succeed as it meets the minimum security requirement
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_parameters_sha256_above_threshold() {
        // Test parameters above the security threshold for SHA256
        let params = Pbkdf2ParamsBuilder {
            c: 262145, // Just above 2^18
            salt: vec![0u8; 32],
            prf: PseudoRandomFunction::Sha256,
        };

        let result = Pbkdf2::try_from(params);

        assert!(result.is_ok());
    }

    #[test]
    fn test_pbkdf2_kdf_serialization() {
        use hex;
        use serde_json;

        // Create a Pbkdf2 with test vector parameters
        let salt = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let params = Pbkdf2ParamsBuilder {
            c: 262144, // 2^18
            salt,
            prf: PseudoRandomFunction::Sha256,
        };

        let kdf = Pbkdf2::try_from(params).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&kdf).unwrap();

        // Parse back to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify the JSON structure matches ERC-2335 format
        assert_eq!(parsed["function"], "pbkdf2");
        assert_eq!(parsed["params"]["dklen"], 32);
        assert_eq!(parsed["params"]["c"], 262144);
        assert_eq!(parsed["params"]["prf"], "hmac-sha256");
        assert_eq!(
            parsed["params"]["salt"],
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        );
        assert_eq!(parsed["message"], "");

        // Test deserialization roundtrip
        let deserialized_kdf: Pbkdf2 = serde_json::from_str(&json).unwrap();

        // Verify the deserialized KDF has the same parameters
        assert_eq!(deserialized_kdf.params.dklen, 32);
        assert_eq!(deserialized_kdf.params.c, 262144);
        assert!(matches!(
            deserialized_kdf.params.prf,
            PseudoRandomFunction::Sha256
        ));
        assert_eq!(
            deserialized_kdf.params.salt,
            hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap()
        );
    }

    #[test]
    fn test_pbkdf2_kdf_deserialization_from_erc2335_format() {
        use serde_json;

        // Test JSON in exact ERC-2335 format
        let json = r#"{
            "function": "pbkdf2",
            "params": {
                "dklen": 32,
                "c": 262144,
                "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        }"#;

        let kdf: Pbkdf2 = serde_json::from_str(json).unwrap();

        // Verify parameters
        assert_eq!(kdf.params.dklen, 32);
        assert_eq!(kdf.params.c, 262144);
        assert!(matches!(kdf.params.prf, PseudoRandomFunction::Sha256));
        assert_eq!(
            kdf.params.salt,
            hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap()
        );
    }

    #[test]
    fn test_pbkdf2_kdf_deserialization_invalid_function() {
        use serde_json;

        // Test with wrong function name
        let json = r#"{
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "c": 262144,
                "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        }"#;

        let result: Result<Pbkdf2, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_prf_serialization() {
        use serde_json;

        // Test SHA256 PRF serialization
        let prf_sha256 = PseudoRandomFunction::Sha256;
        let json_sha256 = serde_json::to_string(&prf_sha256).unwrap();
        assert_eq!(json_sha256, "\"hmac-sha256\"");

        // Test SHA512 PRF serialization
        let prf_sha512 = PseudoRandomFunction::Sha512;
        let json_sha512 = serde_json::to_string(&prf_sha512).unwrap();
        assert_eq!(json_sha512, "\"hmac-sha512\"");
    }

    #[test]
    fn test_prf_deserialization() {
        use serde_json;

        // Test SHA256 PRF deserialization
        let prf_sha256: PseudoRandomFunction = serde_json::from_str("\"hmac-sha256\"").unwrap();
        assert!(matches!(prf_sha256, PseudoRandomFunction::Sha256));

        // Test SHA512 PRF deserialization
        let prf_sha512: PseudoRandomFunction = serde_json::from_str("\"hmac-sha512\"").unwrap();
        assert!(matches!(prf_sha512, PseudoRandomFunction::Sha512));

        // Test invalid PRF deserialization
        let result: Result<PseudoRandomFunction, _> = serde_json::from_str("\"invalid-prf\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_kdf_with_sha512() {
        use hex;
        use serde_json;

        // Create a Pbkdf2 with SHA512 PRF
        let salt = hex::decode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            .unwrap();
        let params = Pbkdf2ParamsBuilder {
            c: 300000, // Higher iteration count
            salt,
            prf: PseudoRandomFunction::Sha512,
        };

        let kdf = Pbkdf2::try_from(params).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&kdf).unwrap();

        // Parse back to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify the JSON structure
        assert_eq!(parsed["function"], "pbkdf2");
        assert_eq!(parsed["params"]["dklen"], 32);
        assert_eq!(parsed["params"]["c"], 300000);
        assert_eq!(parsed["params"]["prf"], "hmac-sha512");
        assert_eq!(
            parsed["params"]["salt"],
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
        assert_eq!(parsed["message"], "");

        // Test deserialization roundtrip
        let deserialized_kdf: Pbkdf2 = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized_kdf.params.prf,
            PseudoRandomFunction::Sha512
        ));
    }
}
