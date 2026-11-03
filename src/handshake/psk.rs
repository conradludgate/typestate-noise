use std::marker::PhantomData;

use zeroize::Zeroizing;

use crate::crypto::{Crypto, PublicKey};

use super::{
    core::{present, Core, Message},
    states::*,
    Complete, Error, Handshake, Transport, Written, IK, XX,
};

/// An owned 32-byte Noise PSK, erased on drop. It is consumed at its token.
pub struct Psk(pub(super) Zeroizing<[u8; 32]>);

impl Psk {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Sealed compile-time PSK modes. No mode or PSK is stored in the core.
pub trait PskMode: super::sealed::Sealed {
    #[doc(hidden)]
    const ENABLED: bool;
}

/// A handshake without PSK tokens or the PSK-specific ephemeral mixing rule.
pub struct NoPsk;
/// A PSK token at the beginning of message 1.
pub struct Psk0;
/// A PSK token after the final key token of message 2, before its payload.
pub struct Psk2;
/// Independent PSK tokens at both positions 0 and 2.
pub struct Psk0And2;

macro_rules! mode {
    ($($name:ty => $enabled:expr),* $(,)?) => {$(
        impl super::sealed::Sealed for $name {}
        impl PskMode for $name { const ENABLED: bool = $enabled; }
    )*};
}

mode!(NoPsk => false, Psk0 => true, Psk2 => true, Psk0And2 => true);

macro_rules! constructors_psk0 {
    ($initiator:ident, $responder:ident, $mode:ty, $xx:literal, $ik:literal) => {
        impl XX {
            pub fn $initiator<C: Crypto>(
                prologue: &[u8],
                psk: Psk,
            ) -> Result<Handshake<C, XxInitiatorWrite1, $mode>, Error> {
                let mut core = Core::new($xx, prologue)?;
                core.mix_psk(psk)?;
                Ok(Handshake::from_core(core))
            }
            pub fn $responder<C: Crypto>(
                prologue: &[u8],
                psk: Psk,
            ) -> Result<Handshake<C, XxResponderRead1, $mode>, Error> {
                let mut core = Core::new($xx, prologue)?;
                core.mix_psk(psk)?;
                Ok(Handshake::from_core(core))
            }
        }
        impl IK {
            pub fn $initiator<C: Crypto>(
                prologue: &[u8],
                local_static: PublicKey<C>,
                remote_static: PublicKey<C>,
                psk: Psk,
            ) -> Result<Handshake<C, IkInitiatorWrite1, $mode>, Error> {
                let mut core = Core::new($ik, prologue)?;
                core.mix_hash(remote_static.as_ref());
                core.s = Some(local_static);
                core.rs = Some(remote_static);
                core.mix_psk(psk)?;
                Ok(Handshake::from_core(core))
            }
            pub fn $responder<C: Crypto>(
                prologue: &[u8],
                local_static: PublicKey<C>,
                psk: Psk,
            ) -> Result<Handshake<C, IkResponderRead1, $mode>, Error> {
                let mut core = Core::new($ik, prologue)?;
                core.mix_hash(local_static.as_ref());
                core.s = Some(local_static);
                core.mix_psk(psk)?;
                Ok(Handshake::from_core(core))
            }
        }
    };
}

constructors_psk0!(initiator_psk0, responder_psk0, Psk0, "XXpsk0", "IKpsk0");
constructors_psk0!(
    initiator_psk0_psk2,
    responder_psk0_psk2,
    Psk0And2,
    "XXpsk0+psk2",
    "IKpsk0+psk2"
);

impl XX {
    pub fn initiator_psk2<C: Crypto>(
        prologue: &[u8],
    ) -> Result<Handshake<C, XxInitiatorWrite1, Psk2>, Error> {
        Ok(Handshake::from_core(Core::new("XXpsk2", prologue)?))
    }
    pub fn responder_psk2<C: Crypto>(
        prologue: &[u8],
    ) -> Result<Handshake<C, XxResponderRead1, Psk2>, Error> {
        Ok(Handshake::from_core(Core::new("XXpsk2", prologue)?))
    }
}

impl IK {
    pub fn initiator_psk2<C: Crypto>(
        prologue: &[u8],
        local_static: PublicKey<C>,
        remote_static: PublicKey<C>,
    ) -> Result<Handshake<C, IkInitiatorWrite1, Psk2>, Error> {
        let mut core = Core::new("IKpsk2", prologue)?;
        core.mix_hash(remote_static.as_ref());
        core.s = Some(local_static);
        core.rs = Some(remote_static);
        Ok(Handshake::from_core(core))
    }
    pub fn responder_psk2<C: Crypto>(
        prologue: &[u8],
        local_static: PublicKey<C>,
    ) -> Result<Handshake<C, IkResponderRead1, Psk2>, Error> {
        let mut core = Core::new("IKpsk2", prologue)?;
        core.mix_hash(local_static.as_ref());
        core.s = Some(local_static);
        Ok(Handshake::from_core(core))
    }
}

/// A PSK2 token awaiting its secret, before processing the message payload.
/// This owns the same core and borrows the same message as the preceding state.
/// It may be held across an await; dropping it abandons the handshake.
#[must_use]
pub struct PskRequest<'a, C: Crypto, Step, M: PskMode = Psk2> {
    pub(super) core: Box<Core<C>>,
    pub(super) message: Message<'a>,
    step: PhantomData<(Step, M)>,
}

impl<'a, C: Crypto, Step, M: PskMode> PskRequest<'a, C, Step, M> {
    pub(super) fn new(core: Box<Core<C>>, message: Message<'a>) -> Self {
        Self {
            core,
            message,
            step: PhantomData,
        }
    }
}

// These finish helpers are shared by normal message-2 paths and by PSK2
// continuations after MixKeyAndHash. Each prefix has already installed a key.
impl<'a, C: Crypto, M: PskMode> PskRequest<'a, C, XxInitiatorPsk2, M> {
    pub(super) fn finish(mut self) -> Result<Written<'a, C, XxInitiatorWrite3, M>, Error> {
        // SAFETY: the message-2 prefix installed the es key, optionally replaced by PSK2.
        let payload = unsafe { self.message.decrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), payload))
    }

    /// The peer static identity, authenticated by DH after the payload succeeds.
    /// Use this to select a PSK; possession of the PSK is not established yet.
    pub fn remote_static(&self) -> &PublicKey<C> {
        // SAFETY: reading the message-2 prefix decrypted and installed rs.
        unsafe { present(&self.core.rs) }
    }
}

impl<'a, C: Crypto, M: PskMode> PskRequest<'a, C, XxResponderPsk2, M> {
    pub(super) fn finish(mut self) -> Result<Written<'a, C, XxResponderRead3, M>, Error> {
        // SAFETY: the es result installed a key, optionally replaced by PSK2.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), message))
    }
}

impl<'a, C: Crypto, M: PskMode> PskRequest<'a, C, IkInitiatorPsk2, M> {
    pub fn remote_static(&self) -> &PublicKey<C> {
        // SAFETY: the IK initiator constructor installed its pre-known rs.
        unsafe { present(&self.core.rs) }
    }

    pub(super) fn finish(mut self) -> Result<Complete<'a, C>, Error> {
        // SAFETY: the se result installed a key, optionally replaced by PSK2.
        let payload = unsafe { self.message.decrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, true)?, payload))
    }
}

impl<'a, C: Crypto, M: PskMode> PskRequest<'a, C, IkResponderPsk2, M> {
    pub(super) fn finish(mut self) -> Result<Complete<'a, C>, Error> {
        // SAFETY: the message-2 prefix installed the se key, optionally replaced by PSK2.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, false)?, message))
    }

    pub fn remote_static(&self) -> &PublicKey<C> {
        // SAFETY: message 1 installed/authenticated rs before reaching message 2.
        unsafe { present(&self.core.rs) }
    }
}

macro_rules! provide {
    ($mode:ty, $step:ty, $result:ty) => {
        impl<'a, C: Crypto> PskRequest<'a, C, $step, $mode> {
            /// Mix and erase this PSK, then authenticate or encrypt the payload.
            pub fn provide_psk(mut self, psk: Psk) -> Result<$result, Error> {
                self.core.mix_psk(psk)?;
                self.finish()
            }
        }
    };
}

macro_rules! provide_mode {
    ($mode:ty) => {
        provide!(
            $mode,
            XxInitiatorPsk2,
            Written<'a, C, XxInitiatorWrite3, $mode>
        );
        provide!(
            $mode,
            XxResponderPsk2,
            Written<'a, C, XxResponderRead3, $mode>
        );
        provide!($mode, IkInitiatorPsk2, Complete<'a, C>);
        provide!($mode, IkResponderPsk2, Complete<'a, C>);
    };
}

provide_mode!(Psk2);
provide_mode!(Psk0And2);
