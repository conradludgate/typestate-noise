use crate::crypto::{Cipher, Crypto, Dh, PublicKey};

use super::{
    core::{Core, Message},
    states::*,
    Complete, DhRequest, DhResult, Error, Handshake, NoPsk, Psk0, Psk0And2, Psk2, PskMode,
    PskRequest, Transport, Written, IK, XX,
};

impl XX {
    pub fn initiator<C: Crypto>(prologue: &[u8]) -> Result<Handshake<C, XxInitiatorWrite1>, Error> {
        Ok(Handshake::from_core(Core::new("XX", prologue)?))
    }

    pub fn responder<C: Crypto>(prologue: &[u8]) -> Result<Handshake<C, XxResponderRead1>, Error> {
        Ok(Handshake::from_core(Core::new("XX", prologue)?))
    }
}

impl IK {
    pub fn initiator<C: Crypto>(
        prologue: &[u8],
        local_static: PublicKey<C>,
        remote_static: PublicKey<C>,
    ) -> Result<Handshake<C, IkInitiatorWrite1>, Error> {
        let mut core = Core::new("IK", prologue)?;
        core.mix_hash(remote_static.as_ref());
        core.s = Some(local_static);
        core.rs = Some(remote_static);
        Ok(Handshake::from_core(core))
    }

    pub fn responder<C: Crypto>(
        prologue: &[u8],
        local_static: PublicKey<C>,
    ) -> Result<Handshake<C, IkResponderRead1>, Error> {
        let mut core = Core::new("IK", prologue)?;
        core.mix_hash(local_static.as_ref());
        core.s = Some(local_static);
        Ok(Handshake::from_core(core))
    }
}

// Only the five sending states get these entry points. The macro keeps the
// copying and in-place APIs on exactly the same checked transition path.
macro_rules! writer {
    ([$($generics:tt)*], $mode:ty, $step:ty, $offset:expr, $overhead:expr, [$($key:ident),*], $result:ty,
        |$state:ident, $message:ident| $body:block) => {
        impl<$($generics)*> Handshake<C, $step, $mode> {
            /// Plaintext starts here for `write_message_in_place`.
            pub const PAYLOAD_OFFSET: usize = $offset;
            /// Additional bytes required beyond the plaintext payload.
            pub const OVERHEAD: usize = $overhead;

            /// Copy a payload into the caller's output buffer and process the message.
            pub fn write_message<'a>(self, $($key: PublicKey<C>,)* payload: &[u8], output: &'a mut [u8]) -> Result<$result, Error> {
                let message = Message::write(output, Self::OVERHEAD, payload.len())?;
                message.bytes[Self::PAYLOAD_OFFSET..Self::PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
                self.start_write(message, $($key,)*)
            }

            /// Process plaintext already at `PAYLOAD_OFFSET` without copying it.
            pub fn write_message_in_place<'a>(self, $($key: PublicKey<C>,)* output: &'a mut [u8], payload_len: usize) -> Result<$result, Error> {
                let message = Message::write(output, Self::OVERHEAD, payload_len)?;
                self.start_write(message, $($key,)*)
            }

            fn start_write<'a>(self, message: Message<'a>, $($key: PublicKey<C>,)*) -> Result<$result, Error> {
                #[allow(unused_mut)] let mut $state = self;
                #[allow(unused_mut)] let mut $message = message;
                $body
            }
        }
    };
}

writer!(
    [C: Crypto, M: PskMode], M,
    XxInitiatorWrite1,
    C::Dh::PUBLIC_KEY_LEN,
    C::Dh::PUBLIC_KEY_LEN + if M::ENABLED { C::Cipher::TAG_LEN } else { 0 },
    [],
    Written<'a, C, XxInitiatorRead2, M>,
    |state, message| {
        message.write_e::<C, M>(&mut state.core)?;
        let bytes = if M::ENABLED {
            // SAFETY: in PSK mode, the e token just called MixKey(e.public).
            unsafe { message.encrypt_payload(&mut state.core)? }
        } else {
            state.core.mix_hash(&message.bytes[message.position..]);
            message.bytes
        };
        Ok((state.transition(), bytes))
    }
);

impl<C: Crypto, M: PskMode> Handshake<C, XxResponderRead1, M> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<Written<'a, C, XxResponderWrite2, M>, Error> {
        let mut message = Message::read(input, Handshake::<C, XxInitiatorWrite1, M>::OVERHEAD)?;
        message.read_e::<C, M>(&mut self.core)?;
        let payload = if M::ENABLED {
            // SAFETY: in PSK mode, reading e just installed its cipher key.
            unsafe { message.decrypt_payload(&mut self.core)? }
        } else {
            let payload = &mut message.bytes[message.position..];
            self.core.mix_hash(payload);
            payload
        };
        Ok((self.transition(), payload))
    }
}

writer!(
    [C: Crypto, M: PskMode], M,
    XxResponderWrite2,
    2 * C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    2 * C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [local_static],
    DhRequest<'a, C, XxResponderDh2, M>,
    |state, message| {
        state.core.s = Some(local_static);
        message.write_e::<C, M>(&mut state.core)?;
        // SAFETY: message 1 installed re; write_e installed e; s was set above.
        unsafe {
            state.core.ee()?;
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // es: local static / remote ephemeral
    }
);

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, XxResponderDh2, M> {
    fn resume_prefix(
        mut self,
        shared: DhResult<C>,
    ) -> Result<PskRequest<'a, C, XxResponderPsk2, M>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        Ok(PskRequest::new(self.core, self.message))
    }
}

impl<C: Crypto, M: PskMode> Handshake<C, XxInitiatorRead2, M> {
    fn read_prefix<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<PskRequest<'a, C, XxInitiatorPsk2, M>, Error> {
        let mut message = Message::read(input, Handshake::<C, XxResponderWrite2, M>::OVERHEAD)?;
        message.read_e::<C, M>(&mut self.core)?;
        // SAFETY: write1 installed e, read_e installed re. ee installs the
        // cipher key; read_s then installs rs for ephemeral_static (es).
        unsafe {
            self.core.ee()?;
            message.read_s(&mut self.core)?;
            self.core.ephemeral_static()?;
        }
        Ok(PskRequest::new(self.core, message))
    }
}

writer!(
    [C: Crypto, M: PskMode], M,
    XxInitiatorWrite3,
    C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [local_static],
    DhRequest<'a, C, XxInitiatorDh3, M>,
    |state, message| {
        state.core.s = Some(local_static);
        // SAFETY: s was set above and reading message 2 installed the cipher key.
        unsafe {
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // se: local static / remote ephemeral
    }
);

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, XxInitiatorDh3, M> {
    pub fn resume(mut self, shared: DhResult<C>) -> Result<Complete<'a, C>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: MixKey just installed the payload key.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, true)?, message))
    }
}

impl<C: Crypto, M: PskMode> Handshake<C, XxResponderRead3, M> {
    pub fn read_message<'a>(mut self, input: &'a mut [u8]) -> Result<Complete<'a, C>, Error> {
        let mut message = Message::read(input, Handshake::<C, XxInitiatorWrite3, M>::OVERHEAD)?;
        // SAFETY: message 2 installed the cipher key and local e; read_s
        // installs rs before ephemeral_static (se) is called.
        unsafe {
            message.read_s(&mut self.core)?;
            self.core.ephemeral_static()?;
        }
        // SAFETY: se installed the payload key.
        let payload = unsafe { message.decrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, false)?, payload))
    }
}

writer!(
    [C: Crypto, M: PskMode], M,
    IkInitiatorWrite1,
    2 * C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    2 * C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [],
    DhRequest<'a, C, IkInitiatorDh1, M>,
    |state, message| {
        message.write_e::<C, M>(&mut state.core)?;
        // SAFETY: the constructor installed rs and s; write_e installed e.
        // es installs the cipher key before the encrypted static is written.
        unsafe {
            state.core.ephemeral_static()?;
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // ss: local static / remote static
    }
);

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, IkInitiatorDh1, M> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<Written<'a, C, IkInitiatorRead2, M>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: MixKey just installed the payload key.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), message))
    }
}

impl<C: Crypto, M: PskMode> Handshake<C, IkResponderRead1, M> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<DhRequest<'a, C, IkResponderDh1Es, M>, Error> {
        let mut message = Message::read(input, Handshake::<C, IkInitiatorWrite1, M>::OVERHEAD)?;
        message.read_e::<C, M>(&mut self.core)?;
        Ok(self.pause(message)) // es: local static / remote ephemeral
    }
}

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, IkResponderDh1Es, M> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<DhRequest<'a, C, IkResponderDh1Ss, M>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: es just installed the key needed to decrypt the peer static key.
        unsafe {
            self.message.read_s(&mut self.core)?;
        }
        Ok(DhRequest {
            core: self.core,
            message: self.message,
            step: std::marker::PhantomData,
        })
    }
}

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, IkResponderDh1Ss, M> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<Written<'a, C, IkResponderWrite2, M>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: ss just installed the payload key.
        let payload = unsafe { self.message.decrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), payload))
    }
}

impl<C: Crypto, M: PskMode> Handshake<C, IkResponderWrite2, M> {
    fn write_prefix<'a>(
        mut self,
        mut message: Message<'a>,
    ) -> Result<PskRequest<'a, C, IkResponderPsk2, M>, Error> {
        message.write_e::<C, M>(&mut self.core)?;
        // SAFETY: reading message 1 installed re and rs; write_e installed e.
        unsafe {
            self.core.ee()?;
            self.core.ephemeral_static()?; // se
        }
        Ok(PskRequest::new(self.core, message))
    }
}

impl<C: Crypto, M: PskMode> Handshake<C, IkInitiatorRead2, M> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<DhRequest<'a, C, IkInitiatorDh2, M>, Error> {
        let mut message = Message::read(input, C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN)?;
        message.read_e::<C, M>(&mut self.core)?;
        // SAFETY: writing message 1 installed e, and read_e just installed re.
        unsafe {
            self.core.ee()?;
        }
        Ok(self.pause(message)) // se: local static / remote ephemeral
    }
}

impl<'a, C: Crypto, M: PskMode> DhRequest<'a, C, IkInitiatorDh2, M> {
    fn resume_prefix(
        mut self,
        shared: DhResult<C>,
    ) -> Result<PskRequest<'a, C, IkInitiatorPsk2, M>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        Ok(PskRequest::new(self.core, self.message))
    }
}

// The message-2 prefixes are identical across modes. Only modes carrying a psk2
// token return a public PSK request; the others immediately process the payload.
macro_rules! without_psk2 {
    ($mode:ty) => {
        impl<'a, C: Crypto> DhRequest<'a, C, XxResponderDh2, $mode> {
            pub fn resume(self, shared: DhResult<C>) -> Result<Written<'a, C, XxResponderRead3, $mode>, Error> {
                self.resume_prefix(shared)?.finish()
            }
        }
        impl<C: Crypto> Handshake<C, XxInitiatorRead2, $mode> {
            pub fn read_message<'a>(self, input: &'a mut [u8]) -> Result<Written<'a, C, XxInitiatorWrite3, $mode>, Error> {
                self.read_prefix(input)?.finish()
            }
        }
        writer!([C: Crypto], $mode, IkResponderWrite2,
            C::Dh::PUBLIC_KEY_LEN, C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
            [], Complete<'a, C>, |state, message| {
                state.write_prefix(message)?.finish()
            }
        );
        impl<'a, C: Crypto> DhRequest<'a, C, IkInitiatorDh2, $mode> {
            pub fn resume(self, shared: DhResult<C>) -> Result<Complete<'a, C>, Error> {
                self.resume_prefix(shared)?.finish()
            }
        }
    };
}

macro_rules! with_psk2 {
    ($mode:ty) => {
        impl<'a, C: Crypto> DhRequest<'a, C, XxResponderDh2, $mode> {
            pub fn resume(self, shared: DhResult<C>) -> Result<PskRequest<'a, C, XxResponderPsk2, $mode>, Error> {
                self.resume_prefix(shared)
            }
        }
        impl<C: Crypto> Handshake<C, XxInitiatorRead2, $mode> {
            pub fn read_message<'a>(self, input: &'a mut [u8]) -> Result<PskRequest<'a, C, XxInitiatorPsk2, $mode>, Error> {
                self.read_prefix(input)
            }
        }
        writer!([C: Crypto], $mode, IkResponderWrite2,
            C::Dh::PUBLIC_KEY_LEN, C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
            [], PskRequest<'a, C, IkResponderPsk2, $mode>, |state, message| {
                state.write_prefix(message)
            }
        );
        impl<'a, C: Crypto> DhRequest<'a, C, IkInitiatorDh2, $mode> {
            pub fn resume(self, shared: DhResult<C>) -> Result<PskRequest<'a, C, IkInitiatorPsk2, $mode>, Error> {
                self.resume_prefix(shared)
            }
        }
    };
}

without_psk2!(NoPsk);
without_psk2!(Psk0);
with_psk2!(Psk2);
with_psk2!(Psk0And2);
