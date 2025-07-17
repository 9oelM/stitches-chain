use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Purpose is set to 12381 which is the name of the curve (BLS12-381)
pub const PURPOSE: u32 = 12381;

/// Coin type for Ethereum 2.0 is 3600 (60^2)
/// where 60 is Ethereum 1.0's coin type
pub const ETH2_COIN_TYPE: u32 = 3600;

#[derive(Debug, Error)]
pub enum PathError {
    #[error("Invalid path format. Expected m/purpose/coin_type/account/use")]
    InvalidFormat,
    #[error("Purpose must be {PURPOSE} for BLS12-381")]
    InvalidPurpose,
    #[error("Invalid coin type")]
    InvalidCoinType,
    #[error("Invalid account index")]
    InvalidAccount,
    #[error("Invalid use index")]
    InvalidUse,
}

/// Represents a BLS12-381 key derivation path as defined in [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)
///
/// Format: m/purpose/coin_type/account/use
///
/// Example withdrawal key path: m/12381/3600/0/0
/// Example signing key path: m/12381/3600/0/0/0
#[derive(Debug, Clone, PartialEq)]
pub struct DerivationPath {
    /// Must be 12381 for BLS12-381
    purpose: u32,
    /// Coin type (3600 for ETH2)
    coin_type: u32,
    /// Account index for different sets of keys
    account: u32,
    /// Use case index (0 for withdrawal keys)
    use_index: u32,
    /// Optional extra index for signing keys
    signing_index: Option<u32>,
}

impl DerivationPath {
    /// Create a new withdrawal key path
    pub fn new_withdrawal(account: u32) -> Self {
        Self {
            purpose: PURPOSE,
            coin_type: ETH2_COIN_TYPE,
            account,
            use_index: 0,
            signing_index: None,
        }
    }

    /// Create a new signing key path
    pub fn new_signing(account: u32) -> Self {
        Self {
            purpose: PURPOSE,
            coin_type: ETH2_COIN_TYPE,
            account,
            use_index: 0,
            signing_index: Some(0),
        }
    }

    /// Check if this is a withdrawal key path
    ///
    /// The path for withdrawal keys is m/12381/3600/i/0 where i indicates the ith set of validator keys.
    pub fn is_withdrawal(&self) -> bool {
        self.signing_index.is_none()
    }

    /// Check if this is a signing key path
    ///
    /// The path for the signing key is m/12381/3600/i/0/0 where again,
    /// i indicates the ith set of validator keys.
    ///  
    /// Another way of phrasing this is that the signing key is
    /// the 0th child of the associated withdrawal key for that validator.
    pub fn is_signing(&self) -> bool {
        self.signing_index.is_some()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(signing) = self.signing_index {
            write!(
                f,
                "m/{}/{}/{}/{}/{}",
                self.purpose, self.coin_type, self.account, self.use_index, signing
            )
        } else {
            write!(
                f,
                "m/{}/{}/{}/{}",
                self.purpose, self.coin_type, self.account, self.use_index
            )
        }
    }
}

impl FromStr for DerivationPath {
    type Err = PathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        // Remove 'm/' prefix
        let path = path.strip_prefix("m/").ok_or(PathError::InvalidFormat)?;

        // Split into components
        let components: Vec<&str> = path.split('/').collect();

        // Validate components length
        match components.len() {
            4 | 5 => (), // Valid lengths for withdrawal and signing paths
            _ => return Err(PathError::InvalidFormat),
        }

        // Parse components
        let purpose = components[0]
            .parse()
            .map_err(|_| PathError::InvalidFormat)?;
        if purpose != PURPOSE {
            return Err(PathError::InvalidPurpose);
        }

        let coin_type = components[1]
            .parse()
            .map_err(|_| PathError::InvalidFormat)?;

        let account = components[2]
            .parse()
            .map_err(|_| PathError::InvalidAccount)?;

        let use_index = components[3].parse().map_err(|_| PathError::InvalidUse)?;

        let signing_index = if components.len() == 5 {
            Some(
                components[4]
                    .parse()
                    .map_err(|_| PathError::InvalidFormat)?,
            )
        } else {
            None
        };

        Ok(Self {
            purpose,
            coin_type,
            account,
            use_index,
            signing_index,
        })
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_withdrawal_path() {
        let path = DerivationPath::new_withdrawal(0);
        assert_eq!(path.to_string(), "m/12381/3600/0/0");
        assert!(path.is_withdrawal());
        assert!(!path.is_signing());
    }

    #[test]
    fn test_signing_path() {
        let path = DerivationPath::new_signing(0);
        assert_eq!(path.to_string(), "m/12381/3600/0/0/0");
        assert!(!path.is_withdrawal());
        assert!(path.is_signing());
    }

    #[test]
    fn test_parse_path() {
        let path = DerivationPath::from_str("m/12381/3600/0/0").unwrap();
        assert!(path.is_withdrawal());

        let path = DerivationPath::from_str("m/12381/3600/0/0/0").unwrap();
        assert!(path.is_signing());
    }

    #[test]
    fn test_invalid_paths() {
        assert!(DerivationPath::from_str("m/12382/3600/0/0").is_err());
        assert!(DerivationPath::from_str("m/12381/3600/0").is_err());
        assert!(DerivationPath::from_str("not_a_path").is_err());
    }
}
