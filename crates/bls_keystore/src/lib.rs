//! BLS12-381 Keystore Implementation (ERC-2335)
//! | Step | Algorithm      | Purpose                                             |
//! |------|---------------|------------------------------------------------------|
//! | 1    | BLS           | Generate the secret key (private key) for signing    |
//! | 2    | PBKDF2/Scrypt | Derive an encryption key from the user's password    |
//! | 3    | AES-128-CTR   | Encrypt the BLS secret key using the derived key     |
//! | 4    | SHA-256       | Create a checksum for integrity                      |

pub mod aes_128_cipher;
pub mod derivation_path;
pub mod key_derivation;
pub mod keystore;
pub mod pbkdf;
pub mod scrypt;
pub(crate) mod serde_helper;
pub mod sha256_checksum;
