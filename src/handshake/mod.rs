//! Boxed, consuming typestates for Noise XX and IK.
//!
//! Message framing and I/O belong to the application. A read accepts exactly one
//! complete Noise message. Writes have both a copying convenience method and an
//! in-place method: place plaintext at `PAYLOAD_OFFSET`, provide its length, and
//! reserve `OVERHEAD` additional bytes. Returned slices delimit the message or
//! decrypted payload within the caller's buffer.
//!
//! Static DH pauses own the handshake and borrow the message. Compute the requested
//! DH externally (synchronously or asynchronously), then consume the pause with
//! `resume`. The credential used must correspond to `local_public_key()`. Supplying
//! the correct shared secret is the application's cryptographic responsibility.
//!
//! Any handshake error or abandoned pause drops the handshake. Decryption failures
//! may modify the buffer; do not use its contents as authenticated plaintext.
//!
//! Message order is enforced at compile time:
//! ```compile_fail
//! use typestate_noise::{crypto::DefaultCrypto, handshake::XX};
//! let state = XX::initiator::<DefaultCrypto>(b"").unwrap();
//! state.read_message(&mut []); // The initiator must write message 1 first.
//! ```
//! Handshake states do not expose transport encryption:
//! ```compile_fail
//! use typestate_noise::{crypto::DefaultCrypto, handshake::XX};
//! let mut state = XX::initiator::<DefaultCrypto>(b"").unwrap();
//! state.encrypt(&mut [0; 16]);
//! ```
//! IK requires its credentials at construction:
//! ```compile_fail
//! use typestate_noise::{crypto::DefaultCrypto, handshake::IK};
//! let state = IK::initiator::<DefaultCrypto>(b"");
//! ```
//! An external operation cannot resume the same handshake twice:
//! ```compile_fail
//! use typestate_noise::{crypto::DefaultCrypto, handshake::{DhRequest, DhResult, states::XxResponderDh2}};
//! fn twice(request: DhRequest<'_, DefaultCrypto, XxResponderDh2>) {
//!     let _ = request.resume(DhResult::new([0; 32]));
//!     let _ = request.resume(DhResult::new([0; 32]));
//! }
//! ```

mod core;
mod patterns;

use std::{fmt, marker::PhantomData};

use zeroize::Zeroizing;

use crate::crypto::{Cipher, Crypto, HashOutput, PublicKey, SharedSecret};
use core::{present, Core, Message, MAX_MESSAGE};

/// Runtime failures, as distinct from impossible protocol sequencing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidMessage,
    MessageTooLong,
    BufferTooSmall,
    InvalidSuite,
    Crypto,
    NonceExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// An affine handshake capability. State changes retain the same core allocation.
#[must_use]
pub struct Handshake<C: Crypto, Step> {
    core: Box<Core<C>>,
    step: PhantomData<Step>,
}

impl<C: Crypto, Step> Handshake<C, Step> {
    fn from_core(core: Box<Core<C>>) -> Self {
        Self {
            core,
            step: PhantomData,
        }
    }

    fn transition<Next>(self) -> Handshake<C, Next> {
        Handshake::from_core(self.core)
    }

    fn pause<'a, Next>(self, message: Message<'a>) -> DhRequest<'a, C, Next> {
        DhRequest {
            core: self.core,
            message,
            step: PhantomData,
        }
    }
}

/// A secret DH result bound to a crypto suite and erased when dropped.
pub struct DhResult<C: Crypto>(Zeroizing<SharedSecret<C>>);

impl<C: Crypto> DhResult<C> {
    pub fn new(secret: SharedSecret<C>) -> Self {
        Self(Zeroizing::new(secret))
    }
}

/// A single outstanding static-key DH. It may be held across an `.await`.
/// Dropping it abandons the handshake and releases its borrowed buffer.
#[must_use]
pub struct DhRequest<'a, C: Crypto, Step> {
    core: Box<Core<C>>,
    message: Message<'a>,
    step: PhantomData<Step>,
}

mod sealed {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait StaticDhStep: sealed::Sealed {
    const REMOTE_STATIC: bool;
}

impl<C: Crypto, Step: StaticDhStep> DhRequest<'_, C, Step> {
    /// Public key identifying the local static credential to use.
    pub fn local_public_key(&self) -> &PublicKey<C> {
        // SAFETY: every pause constructor installs/retains the local static key.
        unsafe { present(&self.core.s) }
    }

    pub fn peer_public_key(&self) -> &PublicKey<C> {
        let slot = if Step::REMOTE_STATIC {
            &self.core.rs
        } else {
            &self.core.re
        };
        // SAFETY: the sealed step selects a key installed before creating the pause.
        unsafe { present(slot) }
    }
}

pub type Written<'a, C, S> = (Handshake<C, S>, &'a mut [u8]);
pub type Complete<'a, C> = (Transport<C>, &'a mut [u8]);

/// Transport keys, final handshake hash and peer static identity.
///
/// Completion proves the selected Noise pattern ran successfully; the application
/// must still decide whether the remote static public key is a trusted identity.
/// Both directions retain the handshake's original core allocation.
pub struct Transport<C: Crypto> {
    core: Box<Core<C>>,
}

impl<C: Crypto> Transport<C> {
    fn from_core(mut core: Box<Core<C>>, initiator: bool) -> Result<Self, Error> {
        core.split(initiator)?;
        Ok(Self { core })
    }

    pub fn handshake_hash(&self) -> &HashOutput<C> {
        &self.core.symmetric.h
    }

    pub fn remote_static(&self) -> &PublicKey<C> {
        // SAFETY: XX and IK both obtain the peer static key before completion.
        unsafe { present(&self.core.rs) }
    }

    /// Encrypt in place. The final `TAG_LEN` bytes are reserved for the tag.
    /// Failed encryption still consumes its nonce, so callers cannot reuse it.
    pub fn encrypt<'a>(&mut self, message: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::MessageTooLong);
        }
        // SAFETY: transport construction installs both cipher keys via Split.
        unsafe {
            self.core.symmetric.cipher.encrypt(&[], message)?;
        }
        Ok(message)
    }

    /// Authenticate/decrypt a complete message, returning just its plaintext.
    pub fn decrypt<'a>(&mut self, message: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::MessageTooLong);
        }
        let length = message
            .len()
            .checked_sub(C::Cipher::TAG_LEN)
            .ok_or(Error::InvalidMessage)?;
        // SAFETY: transport construction installs both cipher keys via Split.
        unsafe {
            self.core.receiving.decrypt(&[], message)?;
        }
        Ok(&mut message[..length])
    }
}

/// Noise XX: no pre-known static identities; credentials are supplied when sent.
pub struct XX;

/// Noise IK: the initiator knows the responder's static public key in advance.
pub struct IK;

/// Marker types are normally inferred; they carry no runtime protocol state.
pub mod states {
    pub struct XxInitiatorWrite1;
    pub struct XxInitiatorRead2;
    pub struct XxInitiatorWrite3;
    pub struct XxInitiatorDh3;
    pub struct XxResponderRead1;
    pub struct XxResponderWrite2;
    pub struct XxResponderDh2;
    pub struct XxResponderRead3;
    pub struct IkInitiatorWrite1;
    pub struct IkInitiatorDh1;
    pub struct IkInitiatorRead2;
    pub struct IkInitiatorDh2;
    pub struct IkResponderRead1;
    pub struct IkResponderDh1Es;
    pub struct IkResponderDh1Ss;
    pub struct IkResponderWrite2;
}

macro_rules! dh_step {
    ($($step:ty => $remote_static:expr),* $(,)?) => {$(
        impl sealed::Sealed for $step {}
        impl StaticDhStep for $step { const REMOTE_STATIC: bool = $remote_static; }
    )*};
}

dh_step! {
    states::XxInitiatorDh3 => false,
    states::XxResponderDh2 => false,
    states::IkInitiatorDh1 => true,
    states::IkInitiatorDh2 => false,
    states::IkResponderDh1Es => false,
    states::IkResponderDh1Ss => true,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DefaultCrypto;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn transitions_pauses_and_transport_retain_core_addresses() {
        let i = XX::initiator::<DefaultCrypto>(b"").unwrap();
        let r = XX::responder::<DefaultCrypto>(b"").unwrap();
        let ip = &*i.core as *const _;
        let rp = &*r.core as *const _;
        let mut first = [0; 32];
        let (i, wire) = i.write_message(b"", &mut first).unwrap();
        assert_eq!(ip, &*i.core as *const _);
        let (r, _) = r.read_message(wire).unwrap();
        assert_eq!(rp, &*r.core as *const _);

        let sr = StaticSecret::random();
        let mut second = [0; 96];
        let request = r
            .write_message(PublicKey::from(&sr).to_bytes(), b"", &mut second)
            .unwrap();
        assert_eq!(rp, &*request.core as *const _);
        let shared = DhResult::new(
            sr.diffie_hellman(&(*request.peer_public_key()).into())
                .to_bytes(),
        );
        let (r, wire) = request.resume(shared).unwrap();
        assert_eq!(rp, &*r.core as *const _);
        let (i, _) = i.read_message(wire).unwrap();
        assert_eq!(ip, &*i.core as *const _);

        let si = StaticSecret::random();
        let mut third = [0; 64];
        let request = i
            .write_message(PublicKey::from(&si).to_bytes(), b"", &mut third)
            .unwrap();
        assert_eq!(ip, &*request.core as *const _);
        let shared = DhResult::new(
            si.diffie_hellman(&(*request.peer_public_key()).into())
                .to_bytes(),
        );
        let (i, wire) = request.resume(shared).unwrap();
        assert_eq!(ip, &*i.core as *const _);
        let (r, _) = r.read_message(wire).unwrap();
        assert_eq!(rp, &*r.core as *const _);
        assert!(i.core.e.is_none());
        assert!(r.core.e.is_none());
        assert!(i.core.symmetric.ck.as_ref().iter().all(|b| *b == 0));
        assert!(r.core.symmetric.ck.as_ref().iter().all(|b| *b == 0));
    }
}
