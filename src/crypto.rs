//! Pluggable Noise primitives. Backends are trusted to implement their named algorithms.
//!
//! Associated byte representations must have the advertised lengths. Ephemeral
//! secrets must be fresh for each handshake. Static private keys are deliberately
//! absent from these interfaces: applications perform static DH themselves.

use std::marker::PhantomData;

use zeroize::Zeroize;

use crate::handshake::Error;

/// A DH algorithm and its software ephemeral-key operations.
pub trait Dh {
    const NAME: &'static str;
    const PUBLIC_KEY_LEN: usize;
    type PublicKey: AsRef<[u8]>;
    type EphemeralSecret: Zeroize;
    type SharedSecret: AsRef<[u8]> + Zeroize;

    fn generate() -> Result<Self::EphemeralSecret, Error>;
    fn public(secret: &Self::EphemeralSecret) -> Self::PublicKey;
    fn parse_public(bytes: &[u8]) -> Result<Self::PublicKey, Error>;
    fn dh(
        secret: &Self::EphemeralSecret,
        peer: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Error>;
}

/// An AEAD primitive; the library owns and advances the Noise nonce.
pub trait Cipher {
    const NAME: &'static str;
    const KEY_LEN: usize;
    const TAG_LEN: usize;
    type Key: Zeroize;

    fn key(bytes: &[u8]) -> Result<Self::Key, Error>;
    fn encrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error>;
    fn decrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error>;
}

/// A Noise hash and HMAC. Outputs have exactly `LEN` bytes.
pub trait Hash {
    const NAME: &'static str;
    const LEN: usize;
    type Output: AsRef<[u8]> + AsMut<[u8]> + Zeroize;

    fn zero_output() -> Self::Output;
    fn hash(parts: &[&[u8]]) -> Self::Output;
    fn hmac(key: &[u8], parts: &[&[u8]]) -> Self::Output;
}

/// A compile-time selection of Noise algorithms.
pub trait Crypto {
    type Dh: Dh;
    type Cipher: Cipher;
    type Hash: Hash;
}

pub struct Suite<D, C, H>(PhantomData<(D, C, H)>);

impl<D: Dh, C: Cipher, H: Hash> Crypto for Suite<D, C, H> {
    type Dh = D;
    type Cipher = C;
    type Hash = H;
}

pub type DefaultCrypto = Suite<X25519, ChaChaPoly, Sha256>;
pub type PublicKey<C> = <<C as Crypto>::Dh as Dh>::PublicKey;
pub type EphemeralSecret<C> = <<C as Crypto>::Dh as Dh>::EphemeralSecret;
pub type SharedSecret<C> = <<C as Crypto>::Dh as Dh>::SharedSecret;
pub type CipherKey<C> = <<C as Crypto>::Cipher as Cipher>::Key;
pub type HashOutput<C> = <<C as Crypto>::Hash as Hash>::Output;

pub struct X25519;

impl Dh for X25519 {
    const NAME: &'static str = "25519";
    const PUBLIC_KEY_LEN: usize = 32;
    type PublicKey = [u8; 32];
    type EphemeralSecret = x25519_dalek::ReusableSecret;
    type SharedSecret = [u8; 32];

    fn generate() -> Result<Self::EphemeralSecret, Error> {
        Ok(x25519_dalek::ReusableSecret::random())
    }

    fn public(secret: &Self::EphemeralSecret) -> Self::PublicKey {
        x25519_dalek::PublicKey::from(secret).to_bytes()
    }

    fn parse_public(bytes: &[u8]) -> Result<Self::PublicKey, Error> {
        bytes.try_into().map_err(|_| Error::InvalidMessage)
    }

    fn dh(
        secret: &Self::EphemeralSecret,
        peer: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Error> {
        // Noise permits all-zero X25519 outputs (specification section 12.1).
        Ok(secret.diffie_hellman(&(*peer).into()).to_bytes())
    }
}

pub struct ChaChaPoly;

fn nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut nonce = chacha20poly1305::Nonce::default();
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

impl Cipher for ChaChaPoly {
    const NAME: &'static str = "ChaChaPoly";
    const KEY_LEN: usize = 32;
    const TAG_LEN: usize = 16;
    type Key = [u8; 32];

    fn key(bytes: &[u8]) -> Result<Self::Key, Error> {
        bytes.try_into().map_err(|_| Error::InvalidSuite)
    }

    fn encrypt(
        key: &Self::Key,
        n: u64,
        ad: &[u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        let value = cipher
            .encrypt_in_place_detached(&nonce(n), ad, body)
            .map_err(|_| Error::Crypto)?;
        tag.copy_from_slice(&value);
        Ok(())
    }

    fn decrypt(
        key: &Self::Key,
        n: u64,
        ad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        cipher
            .decrypt_in_place_detached(&nonce(n), ad, body, tag.into())
            .map_err(|_| Error::Crypto)
    }
}

macro_rules! hash {
    ($name:ident, $noise_name:literal, $length:literal) => {
        pub struct $name;

        impl Hash for $name {
            const NAME: &'static str = $noise_name;
            const LEN: usize = $length;
            type Output = [u8; $length];

            fn zero_output() -> Self::Output {
                [0; $length]
            }

            fn hash(parts: &[&[u8]]) -> Self::Output {
                use sha2::Digest;
                let mut hash = sha2::$name::new();
                for part in parts {
                    hash.update(part);
                }
                hash.finalize().into()
            }

            fn hmac(key: &[u8], parts: &[&[u8]]) -> Self::Output {
                use hmac::Mac;
                // SAFETY: HMAC accepts keys of every length.
                let mut mac = unsafe {
                    <hmac::Hmac<sha2::$name> as Mac>::new_from_slice(key).unwrap_unchecked()
                };
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().into()
            }
        }
    };
}

hash!(Sha256, "SHA256", 32);
hash!(Sha512, "SHA512", 64);
