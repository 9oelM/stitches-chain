use thiserror::Error;

use crate::{
    key_derivation::{KeyDerivationError, KeyDerivationMethod},
    keystore::CryptoFunction,
};

#[derive(Debug, Error)]
pub enum CreateScryptKdfParamsError {
    #[error("Insecure scrypt parameters: n * r * p must be at least 2^20")]
    InsecureParameters,
    #[error(
        "Invalid scrypt parameters: n ({n}) must be less than 2^(128 * {r} / 8). Got n={n}, r={r}, 2^(128 * {r} / 8)={upperbound}"
    )]
    InvalidNSize { n: u32, r: u32, upperbound: u64 },
    #[error("Invalid scrypt parameters: n ({n}) must be less than 2**8 - 1")]
    InvalidNSize2 { n: u32 },
    #[error("Invalid scrypt parameters: n ({n}) must be a power of 2")]
    InvalidNPower { n: u32 },
}

#[derive(Debug, Error)]
pub enum ScryptKdfToDerivedKeyError {
    #[error(transparent)]
    InvalidParams(#[from] scrypt::errors::InvalidParams),
    #[error(transparent)]
    InvalidOutputLen(#[from] scrypt::errors::InvalidOutputLen),
}

/// Unprocessed parameters for the Scrypt key derivation function (KDF).
#[derive(Debug, Clone)]
pub struct ScryptKdfParamsBuilder {
    /// CPU/Memory cost parameter.
    ///
    /// Must be a power of 2.
    ///
    /// Higher values increase memory usage and CPU time.
    ///
    /// Example value: 2**18 = 262144
    pub n: u32,
    /// Block size.
    ///
    /// Affects how memory is accessed.
    ///
    /// Larger values increase memory usage.
    ///
    /// Example value: 8
    pub r: u32,
    /// Parallelization factor.
    ///
    /// Number of parallel processing threads.
    ///
    /// Each thread uses 128 * r bytes of memory.
    ///
    /// Example value: 1
    pub p: u32,
    /// Spec does not specify the length of the salt, so we use a `Vec<u8>`
    pub salt: Vec<u8>,
}

/// Parameters for the Scrypt key derivation function (KDF).
#[derive(Debug, Clone)]
pub struct ScryptKdfParams {
    /// Log2 of CPU/Memory cost parameter 'n'.
    log2_n: u8,
    /// Block size.
    ///
    /// Affects how memory is accessed.
    ///
    /// Larger values increase memory usage.
    ///
    /// Example value: 8
    r: u32,
    /// Parallelization factor.
    ///
    /// Number of parallel processing threads.
    ///
    /// Each thread uses 128 * r bytes of memory.
    ///
    /// Example value: 1
    p: u32,
    /// Output of the derived key in bytes.
    ///
    /// For example, dklen = 32 means that the derived key will be 32 bytes long.
    ///
    /// For ERC-2335 keystores, dklen must be 32 bytes (16 for AES-128-CTR + 16 for checksum).
    dklen: u8,
    /// Spec does not specify the length of the salt, so we use a `Vec<u8>`
    salt: Vec<u8>,
}

/// Similar to PBKDF2, but uses Scrypt algorithm.
///
/// More resistant to hardware attacks than PBKDF2.
#[derive(Debug, Clone)]
pub struct ScryptKdf {
    params: ScryptKdfParams,
}

impl ScryptKdf {
    fn new(params: ScryptKdfParams) -> Self {
        ScryptKdf { params }
    }
}

impl KeyDerivationMethod for ScryptKdf {
    fn derive_key(&self, password: &[u8]) -> Result<[u8; 32], KeyDerivationError> {
        // The spec is not finalized, and currently dklen can only be 32 bytes.
        if self.params.dklen != 32 {
            return Err(KeyDerivationError::InvalidDklen {
                dklen: self.params.dklen,
            });
        }

        let mut derived_key = [0u8; 32];

        let scrypt_params = scrypt::Params::new(
            self.params.log2_n,
            self.params.r,
            self.params.p,
            32, // Always 32 bytes for ERC-2335
        )
        .map_err(|e| KeyDerivationError::Scrypt(ScryptKdfToDerivedKeyError::InvalidParams(e)))?;
        scrypt::scrypt(
            password,
            &self.params.salt,
            &scrypt_params,
            &mut derived_key,
        )
        .map_err(|e| KeyDerivationError::Scrypt(ScryptKdfToDerivedKeyError::InvalidOutputLen(e)))?;
        Ok(derived_key)
    }

    fn crypto_function(&self) -> CryptoFunction {
        CryptoFunction::Scrypt
    }

    fn salt(&self) -> Vec<u8> {
        self.params.salt.clone()
    }
}

impl TryFrom<ScryptKdfParamsBuilder> for ScryptKdf {
    type Error = CreateScryptKdfParamsError;

    /// Refer to https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/utils/crypto.py#L21-L26
    /// for parameter validation
    ///
    /// Creates a new ScryptKdf instance from the provided parameters.
    fn try_from(params: ScryptKdfParamsBuilder) -> Result<Self, Self::Error> {
        if params.n * params.r * params.p < 2u32.pow(20) {
            return Err(CreateScryptKdfParamsError::InsecureParameters);
        }

        let upperbound = 2_f32.powf((128 * params.r / 8) as f32);
        if params.n as f32 >= upperbound {
            return Err(CreateScryptKdfParamsError::InvalidNSize {
                n: params.n,
                r: params.r,
                upperbound: upperbound as u64,
            });
        }

        // because ilog2 returns the base 2 logarithm of the number, rounded down.
        // ensure that n is a power of 2 before calling ilog2
        if !params.n.is_power_of_two() {
            return Err(CreateScryptKdfParamsError::InvalidNPower { n: params.n });
        }

        let log2_n: u8 = params
            .n
            .ilog2()
            .try_into()
            .map_err(|_| CreateScryptKdfParamsError::InvalidNSize2 { n: params.n })?;
        Ok(Self::new(ScryptKdfParams {
            log2_n,
            r: params.r,
            p: params.p,
            dklen: 32, // 16 for AES, 16 for checksum
            salt: params.salt,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::scrypt::{CreateScryptKdfParamsError, ScryptKdf, ScryptKdfParamsBuilder};

    #[test]
    fn test_insecure_parameters_below_threshold() {
        // Test case where n * r * p < 2^20 (1048576)
        let params = ScryptKdfParamsBuilder {
            n: 1024, // 2^10
            r: 8,
            p: 1,
            salt: vec![0u8; 32],
        };

        // n * r * p = 1024 * 8 * 1 = 8192, which is < 2^20 = 1048576
        let result = ScryptKdf::try_from(params);

        assert!(matches!(
            result,
            Err(CreateScryptKdfParamsError::InsecureParameters)
        ));
    }

    #[test]
    fn test_insecure_parameters_edge_case() {
        // Test edge case just below the security threshold
        let params = ScryptKdfParamsBuilder {
            n: 2048, // 2^11
            r: 8,
            p: 63, // 2048 * 8 * 63 = 1032192, which is < 2^20 = 1048576
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(params);

        assert!(matches!(
            result,
            Err(CreateScryptKdfParamsError::InsecureParameters)
        ));
    }

    #[test]
    fn test_secure_parameters_at_threshold() {
        // Test parameters exactly at the security threshold
        let params = ScryptKdfParamsBuilder {
            n: 2048, // 2^11
            r: 8,
            p: 64, // 2048 * 8 * 64 = 1048576, which equals 2^20
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(params);

        // This should succeed as it meets the minimum security requirement
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_n_size_exceeds_upperbound() {
        // Test case where n >= 2^(128 * r / 8)
        // For r = 1: upperbound = 2^(128 * 1 / 8) = 2^16 = 65536
        let params = ScryptKdfParamsBuilder {
            n: 65536, // This equals the upperbound for r=1
            r: 1,
            p: 1048, // Make sure n*r*p >= 2^20
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(params);

        assert!(matches!(
            result,
            Err(CreateScryptKdfParamsError::InvalidNSize {
                n: 65536,
                r: 1,
                upperbound: 65536
            })
        ));
    }

    #[test]
    fn test_invalid_n_not_power_of_two() {
        // Test various non-power-of-two values for n
        let test_cases = vec![2047, 2049, 4095, 4097];

        for n in test_cases {
            let params = ScryptKdfParamsBuilder {
                n,
                r: 8,
                p: 2048, // Ensure n*r*p >= 2^20 for most cases
                salt: vec![0u8; 32],
            };

            let result = ScryptKdf::try_from(params);

            assert!(
                matches!(result, Err(CreateScryptKdfParamsError::InvalidNPower { n: test_n }) if test_n == n),
                "n={n} should fail as it's not a power of 2"
            );
        }
    }

    #[test]
    fn test_valid_powers_of_two() {
        // Test that valid powers of two work (when other constraints are met)
        let valid_powers = vec![
            1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
        ];

        for n in valid_powers {
            // Calculate p to ensure n*r*p >= 2^20
            let r = 8u32;
            let min_product = 2u32.pow(20); // 1048576
            let p = (min_product / (n * r)).max(1);

            let params = ScryptKdfParamsBuilder {
                n,
                r,
                p,
                salt: vec![0u8; 32],
            };

            let result = ScryptKdf::try_from(params);

            // Should succeed if n is small enough to not hit the upperbound constraint
            if n < 65536 {
                // 2^16, which is the upperbound for r=8: 2^(128*8/8) = 2^128, but we use smaller values
                assert!(
                    result.is_ok(),
                    "n={n} should succeed as it's a valid power of 2"
                );
            }
        }
    }

    #[test]
    fn test_invalid_n_size2_large_log2() {
        // Test the InvalidNSize2 error which occurs when log2(n) doesn't fit in u8
        // This happens when n >= 2^256, but since n is u32, the maximum log2(n) is 31
        // So this error is actually unreachable with current types, but let's test the boundary

        // The largest power of 2 that fits in u32 is 2^31 = 2147483648
        // But u32::MAX is 4294967295, so 2^31 is within range
        // log2(2^31) = 31, which fits in u8 (max 255)

        // This test demonstrates that the InvalidNSize2 error is currently unreachable
        // with u32 for n, since log2(u32::MAX) < u8::MAX
        let params = ScryptKdfParamsBuilder {
            n: 2147483648, // 2^31, largest power of 2 in u32
            r: 1,
            p: 1,
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(params);

        // This should not trigger InvalidNSize2, but might trigger other errors
        // The actual error depends on the upperbound calculation
        assert!(result.is_err());
    }

    #[test]
    fn test_one_as_n_parameter() {
        // Test n=1 (which is 2^0, a valid power of 2)
        let params = ScryptKdfParamsBuilder {
            n: 1,
            r: 8,
            p: 131072, // 1 * 8 * 131072 = 1048576 = 2^20
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(params);

        // Should succeed as n=1 is a power of 2 and meets security requirements
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_salt() {
        // Test with empty salt (should be allowed by the spec)
        let params = ScryptKdfParamsBuilder {
            n: 1024,
            r: 8,
            p: 128,       // 1024 * 8 * 128 = 1048576 = 2^20
            salt: vec![], // Empty salt
        };

        let result = ScryptKdf::try_from(params);

        assert!(result.is_ok());
    }

    #[test]
    fn test_large_salt() {
        // Test with very large salt
        let params = ScryptKdfParamsBuilder {
            n: 1024,
            r: 8,
            p: 128,
            salt: vec![0u8; 10000], // Very large salt
        };

        let result = ScryptKdf::try_from(params);

        assert!(result.is_ok());
    }

    #[test]
    fn test_boundary_conditions_for_security_threshold() {
        // Test various combinations that are just above and below the security threshold
        let test_cases = vec![
            // (n, r, p, should_pass)
            (1024, 8, 127, false), // 1024 * 8 * 127 = 1040384 < 2^20
            (1024, 8, 128, true),  // 1024 * 8 * 128 = 1048576 = 2^20
            (1024, 8, 129, true),  // 1024 * 8 * 129 = 1056768 > 2^20
            (512, 16, 127, false), // 512 * 16 * 127 = 1040384 < 2^20
            (512, 16, 128, true),  // 512 * 16 * 128 = 1048576 = 2^20
            (2048, 4, 127, false), // 2048 * 4 * 127 = 1040384 < 2^20
            (2048, 4, 128, true),  // 2048 * 4 * 128 = 1048576 = 2^20
        ];

        for (n, r, p, should_pass) in test_cases {
            let params = ScryptKdfParamsBuilder {
                n,
                r,
                p,
                salt: vec![0u8; 32],
            };

            let result = ScryptKdf::try_from(params);

            if should_pass {
                assert!(
                    result.is_ok(),
                    "Parameters n={n}, r={r}, p={p} should pass security check"
                );
            } else {
                assert!(
                    matches!(result, Err(CreateScryptKdfParamsError::InsecureParameters)),
                    "Parameters n={n}, r={r}, p={p} should fail security check"
                );
            }
        }
    }

    #[test]
    fn test_realistic_ethereum_parameters() {
        // Test parameters commonly used in Ethereum keystore implementations
        let ethereum_params = ScryptKdfParamsBuilder {
            n: 262144, // 2^18, common in Ethereum
            r: 8,
            p: 1,
            salt: vec![0u8; 32],
        };

        let result = ScryptKdf::try_from(ethereum_params);
        assert!(
            result.is_ok(),
            "Standard Ethereum scrypt parameters should be valid"
        );

        // Test the actual KDF functionality
        if let Ok(kdf) = result {
            use crate::key_derivation::KeyDerivationMethod;
            let derived_key = kdf.derive_key(b"testpassword");
            assert!(
                derived_key.is_ok(),
                "Key derivation should succeed with valid parameters"
            );
        }
    }
}
