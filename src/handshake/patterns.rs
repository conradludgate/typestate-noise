use crate::crypto::{Cipher, Crypto, Dh, PublicKey};

use super::{
    core::{Core, Message},
    states::*,
    Complete, DhRequest, DhResult, Error, Handshake, Transport, Written, IK, XX,
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
    ($step:ty, $offset:expr, $overhead:expr, [$($key:ident),*], $result:ty,
        |$state:ident, $message:ident| $body:block) => {
        impl<C: Crypto> Handshake<C, $step> {
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
                let mut $state = self;
                let mut $message = message;
                $body
            }
        }
    };
}

writer!(
    XxInitiatorWrite1,
    C::Dh::PUBLIC_KEY_LEN,
    C::Dh::PUBLIC_KEY_LEN,
    [],
    Written<'a, C, XxInitiatorRead2>,
    |state, message| {
        message.write_e(&mut state.core)?;
        state.core.mix_hash(&message.bytes[message.position..]);
        Ok((state.transition(), message.bytes))
    }
);

impl<C: Crypto> Handshake<C, XxResponderRead1> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<Written<'a, C, XxResponderWrite2>, Error> {
        let mut message = Message::read(input, C::Dh::PUBLIC_KEY_LEN)?;
        message.read_e(&mut self.core)?;
        let payload = &mut message.bytes[message.position..];
        self.core.mix_hash(payload);
        Ok((self.transition(), payload))
    }
}

writer!(
    XxResponderWrite2,
    2 * C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    2 * C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [local_static],
    DhRequest<'a, C, XxResponderDh2>,
    |state, message| {
        state.core.s = Some(local_static);
        message.write_e(&mut state.core)?;
        // SAFETY: message 1 installed re; write_e installed e; s was set above.
        unsafe {
            state.core.ee()?;
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // es: local static / remote ephemeral
    }
);

impl<'a, C: Crypto> DhRequest<'a, C, XxResponderDh2> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<Written<'a, C, XxResponderRead3>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: MixKey just installed the key for this payload.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), message))
    }
}

impl<C: Crypto> Handshake<C, XxInitiatorRead2> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<Written<'a, C, XxInitiatorWrite3>, Error> {
        let mut message = Message::read(input, Handshake::<C, XxResponderWrite2>::OVERHEAD)?;
        message.read_e(&mut self.core)?;
        // SAFETY: write1 installed e, read_e installed re. ee installs the
        // cipher key; read_s then installs rs for ephemeral_static (es).
        unsafe {
            self.core.ee()?;
            message.read_s(&mut self.core)?;
            self.core.ephemeral_static()?;
        }
        // SAFETY: es installed the payload key.
        let payload = unsafe { message.decrypt_payload(&mut self.core)? };
        Ok((self.transition(), payload))
    }
}

writer!(
    XxInitiatorWrite3,
    C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [local_static],
    DhRequest<'a, C, XxInitiatorDh3>,
    |state, message| {
        state.core.s = Some(local_static);
        // SAFETY: s was set above and reading message 2 installed the cipher key.
        unsafe {
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // se: local static / remote ephemeral
    }
);

impl<'a, C: Crypto> DhRequest<'a, C, XxInitiatorDh3> {
    pub fn resume(mut self, shared: DhResult<C>) -> Result<Complete<'a, C>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: MixKey just installed the payload key.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, true)?, message))
    }
}

impl<C: Crypto> Handshake<C, XxResponderRead3> {
    pub fn read_message<'a>(mut self, input: &'a mut [u8]) -> Result<Complete<'a, C>, Error> {
        let mut message = Message::read(input, Handshake::<C, XxInitiatorWrite3>::OVERHEAD)?;
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
    IkInitiatorWrite1,
    2 * C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    2 * C::Dh::PUBLIC_KEY_LEN + 2 * C::Cipher::TAG_LEN,
    [],
    DhRequest<'a, C, IkInitiatorDh1>,
    |state, message| {
        message.write_e(&mut state.core)?;
        // SAFETY: the constructor installed rs and s; write_e installed e.
        // es installs the cipher key before the encrypted static is written.
        unsafe {
            state.core.ephemeral_static()?;
            message.write_s(&mut state.core)?;
        }
        Ok(state.pause(message)) // ss: local static / remote static
    }
);

impl<'a, C: Crypto> DhRequest<'a, C, IkInitiatorDh1> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<Written<'a, C, IkInitiatorRead2>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: MixKey just installed the payload key.
        let message = unsafe { self.message.encrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), message))
    }
}

impl<C: Crypto> Handshake<C, IkResponderRead1> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<DhRequest<'a, C, IkResponderDh1Es>, Error> {
        let mut message = Message::read(input, Handshake::<C, IkInitiatorWrite1>::OVERHEAD)?;
        message.read_e(&mut self.core)?;
        Ok(self.pause(message)) // es: local static / remote ephemeral
    }
}

impl<'a, C: Crypto> DhRequest<'a, C, IkResponderDh1Es> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<DhRequest<'a, C, IkResponderDh1Ss>, Error> {
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

impl<'a, C: Crypto> DhRequest<'a, C, IkResponderDh1Ss> {
    pub fn resume(
        mut self,
        shared: DhResult<C>,
    ) -> Result<Written<'a, C, IkResponderWrite2>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: ss just installed the payload key.
        let payload = unsafe { self.message.decrypt_payload(&mut self.core)? };
        Ok((Handshake::from_core(self.core), payload))
    }
}

writer!(
    IkResponderWrite2,
    C::Dh::PUBLIC_KEY_LEN,
    C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN,
    [],
    Complete<'a, C>,
    |state, message| {
        message.write_e(&mut state.core)?;
        // SAFETY: reading message 1 installed re and rs; write_e installed e.
        unsafe {
            state.core.ee()?;
            state.core.ephemeral_static()?; // se
        }
        // SAFETY: se installed the payload key.
        let message = unsafe { message.encrypt_payload(&mut state.core)? };
        Ok((Transport::from_core(state.core, false)?, message))
    }
);

impl<C: Crypto> Handshake<C, IkInitiatorRead2> {
    pub fn read_message<'a>(
        mut self,
        input: &'a mut [u8],
    ) -> Result<DhRequest<'a, C, IkInitiatorDh2>, Error> {
        let mut message = Message::read(input, Handshake::<C, IkResponderWrite2>::OVERHEAD)?;
        message.read_e(&mut self.core)?;
        // SAFETY: writing message 1 installed e, and read_e just installed re.
        unsafe {
            self.core.ee()?;
        }
        Ok(self.pause(message)) // se: local static / remote ephemeral
    }
}

impl<'a, C: Crypto> DhRequest<'a, C, IkInitiatorDh2> {
    pub fn resume(mut self, shared: DhResult<C>) -> Result<Complete<'a, C>, Error> {
        self.core.mix_key(shared.0.as_ref())?;
        // SAFETY: se just installed the payload key.
        let payload = unsafe { self.message.decrypt_payload(&mut self.core)? };
        Ok((Transport::from_core(self.core, true)?, payload))
    }
}
