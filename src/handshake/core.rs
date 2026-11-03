use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{Cipher, CipherKey, Crypto, Dh, EphemeralSecret, Hash, HashOutput, PublicKey};

use super::{Error, Psk, PskMode};

pub(super) const MAX_MESSAGE: usize = 65_535;

pub(super) struct Ephemeral<C: Crypto> {
    pub secret: Zeroizing<EphemeralSecret<C>>,
    pub public: PublicKey<C>,
}

pub(super) struct Core<C: Crypto> {
    pub symmetric: Symmetric<C>,
    pub e: Option<Ephemeral<C>>,
    pub s: Option<PublicKey<C>>,
    pub re: Option<PublicKey<C>>,
    pub rs: Option<PublicKey<C>>,
    // Filled by Split; retains the same allocation in transport mode.
    pub receiving: CipherState<C>,
}

pub(super) struct Symmetric<C: Crypto> {
    pub ck: Zeroizing<HashOutput<C>>,
    pub h: HashOutput<C>,
    pub cipher: CipherState<C>,
}

pub(super) struct CipherState<C: Crypto> {
    key: Option<Zeroizing<CipherKey<C>>>,
    nonce: u64,
}

impl<C: Crypto> CipherState<C> {
    fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn set_key(&mut self, key: CipherKey<C>) {
        self.key = Some(Zeroizing::new(key));
        self.nonce = 0;
    }

    /// # Safety
    /// A key must have been installed by MixKey or Split.
    pub unsafe fn encrypt(&mut self, ad: &[u8], data: &mut [u8]) -> Result<(), Error> {
        let length = data
            .len()
            .checked_sub(C::Cipher::TAG_LEN)
            .ok_or(Error::InvalidMessage)?;
        if self.nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        let nonce = self.nonce;
        // Reserve the nonce even if a custom backend fails after using it.
        self.nonce += 1;
        let (body, tag) = data.split_at_mut(length);
        // SAFETY: inherited from this method's contract.
        let key = unsafe { present(&self.key) };
        C::Cipher::encrypt(key, nonce, ad, body, tag)
    }

    /// # Safety
    /// A key must have been installed by MixKey or Split.
    pub unsafe fn decrypt(&mut self, ad: &[u8], data: &mut [u8]) -> Result<(), Error> {
        let length = data
            .len()
            .checked_sub(C::Cipher::TAG_LEN)
            .ok_or(Error::InvalidMessage)?;
        if self.nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        let (body, tag) = data.split_at_mut(length);
        // SAFETY: inherited from this method's contract.
        let key = unsafe { present(&self.key) };
        C::Cipher::decrypt(key, self.nonce, ad, body, tag)?;
        self.nonce += 1;
        Ok(())
    }
}

/// # Safety
/// The caller's typestate/transition must establish that the slot is populated.
pub(super) unsafe fn present<T>(slot: &Option<T>) -> &T {
    // SAFETY: inherited from the caller. Options retain ordinary drop behavior.
    unsafe { slot.as_ref().unwrap_unchecked() }
}

fn hkdf2<C: Crypto>(
    ck: &HashOutput<C>,
    input: &[u8],
) -> (Zeroizing<HashOutput<C>>, Zeroizing<HashOutput<C>>) {
    let temp = Zeroizing::new(C::Hash::hmac(ck.as_ref(), &[input]));
    let first = Zeroizing::new(C::Hash::hmac(temp.as_ref(), &[&[1]]));
    let second = Zeroizing::new(C::Hash::hmac(temp.as_ref(), &[first.as_ref(), &[2]]));
    (first, second)
}

fn hkdf3<C: Crypto>(ck: &HashOutput<C>, input: &[u8]) -> [Zeroizing<HashOutput<C>>; 3] {
    let temp = Zeroizing::new(C::Hash::hmac(ck.as_ref(), &[input]));
    let first = Zeroizing::new(C::Hash::hmac(temp.as_ref(), &[&[1]]));
    let second = Zeroizing::new(C::Hash::hmac(temp.as_ref(), &[first.as_ref(), &[2]]));
    let third = Zeroizing::new(C::Hash::hmac(temp.as_ref(), &[second.as_ref(), &[3]]));
    [first, second, third]
}

impl<C: Crypto> Core<C> {
    pub fn new(pattern: &'static str, prologue: &[u8]) -> Result<Box<Self>, Error> {
        if C::Hash::LEN < C::Cipher::KEY_LEN || C::Dh::PUBLIC_KEY_LEN == 0 {
            return Err(Error::InvalidSuite);
        }
        let parts = [
            b"Noise_".as_slice(),
            pattern.as_bytes(),
            b"_",
            C::Dh::NAME.as_bytes(),
            b"_",
            C::Cipher::NAME.as_bytes(),
            b"_",
            C::Hash::NAME.as_bytes(),
        ];
        let mut h = C::Hash::zero_output();
        if parts.iter().map(|p| p.len()).sum::<usize>() <= C::Hash::LEN {
            let mut offset = 0;
            for part in parts {
                h.as_mut()[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
            }
        } else {
            h = C::Hash::hash(&parts);
        }
        let mut ck = Zeroizing::new(C::Hash::zero_output());
        ck.as_mut().copy_from_slice(h.as_ref());
        // Even an empty prologue is hashed (Noise section 5.3).
        h = C::Hash::hash(&[h.as_ref(), prologue]);
        Ok(Box::new(Self {
            symmetric: Symmetric {
                ck,
                h,
                cipher: CipherState::empty(),
            },
            e: None,
            s: None,
            re: None,
            rs: None,
            receiving: CipherState::empty(),
        }))
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.symmetric.h = C::Hash::hash(&[self.symmetric.h.as_ref(), data]);
    }

    pub fn mix_key(&mut self, input: &[u8]) -> Result<(), Error> {
        let (ck, key) = hkdf2::<C>(&self.symmetric.ck, input);
        let key = C::Cipher::key(&key.as_ref()[..C::Cipher::KEY_LEN])?;
        self.symmetric.ck.as_mut().copy_from_slice(ck.as_ref());
        self.symmetric.cipher.set_key(key);
        Ok(())
    }

    pub fn mix_psk(&mut self, psk: Psk) -> Result<(), Error> {
        let [ck, hash, key] = hkdf3::<C>(&self.symmetric.ck, psk.0.as_ref());
        let key = C::Cipher::key(&key.as_ref()[..C::Cipher::KEY_LEN])?;
        self.symmetric.ck.as_mut().copy_from_slice(ck.as_ref());
        self.mix_hash(hash.as_ref());
        self.symmetric.cipher.set_key(key);
        Ok(())
    }

    pub fn generate(&mut self) -> Result<(), Error> {
        let secret = Zeroizing::new(C::Dh::generate()?);
        let public = C::Dh::public(&secret);
        self.e = Some(Ephemeral { secret, public });
        Ok(())
    }

    /// # Safety
    /// Local and remote ephemeral keys must be present.
    pub unsafe fn ee(&mut self) -> Result<(), Error> {
        // SAFETY: inherited from this method's contract.
        let shared = Zeroizing::new(C::Dh::dh(&unsafe { present(&self.e) }.secret, unsafe {
            present(&self.re)
        })?);
        self.mix_key(shared.as_ref())
    }

    /// # Safety
    /// The local ephemeral key and remote static key must be present.
    pub unsafe fn ephemeral_static(&mut self) -> Result<(), Error> {
        // SAFETY: inherited from this method's contract.
        let shared = Zeroizing::new(C::Dh::dh(&unsafe { present(&self.e) }.secret, unsafe {
            present(&self.rs)
        })?);
        self.mix_key(shared.as_ref())
    }

    /// # Safety
    /// MixKey must have installed the handshake cipher key.
    pub unsafe fn encrypt(&mut self, data: &mut [u8]) -> Result<(), Error> {
        // SAFETY: inherited from this method's contract.
        unsafe {
            self.symmetric
                .cipher
                .encrypt(self.symmetric.h.as_ref(), data)?;
        }
        self.mix_hash(data);
        Ok(())
    }

    /// # Safety
    /// MixKey must have installed the handshake cipher key.
    pub unsafe fn decrypt<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let length = data
            .len()
            .checked_sub(C::Cipher::TAG_LEN)
            .ok_or(Error::InvalidMessage)?;
        // Hash the original ciphertext before in-place decryption changes it.
        let h = C::Hash::hash(&[self.symmetric.h.as_ref(), data]);
        // SAFETY: inherited from this method's contract.
        unsafe {
            self.symmetric
                .cipher
                .decrypt(self.symmetric.h.as_ref(), data)?;
        }
        self.symmetric.h = h;
        Ok(&mut data[..length])
    }

    pub fn split(&mut self, initiator: bool) -> Result<(), Error> {
        let (first, second) = hkdf2::<C>(&self.symmetric.ck, &[]);
        let (send, recv) = if initiator {
            (&first, &second)
        } else {
            (&second, &first)
        };
        self.symmetric
            .cipher
            .set_key(C::Cipher::key(&send.as_ref()[..C::Cipher::KEY_LEN])?);
        self.receiving
            .set_key(C::Cipher::key(&recv.as_ref()[..C::Cipher::KEY_LEN])?);
        // Drop the ephemeral secret in its slot; transport needs neither it nor ck.
        self.e = None;
        self.symmetric.ck.zeroize();
        Ok(())
    }
}

pub(super) struct Message<'a> {
    pub bytes: &'a mut [u8],
    pub position: usize,
}

impl<'a> Message<'a> {
    pub fn read(bytes: &'a mut [u8], overhead: usize) -> Result<Self, Error> {
        if bytes.len() < overhead || bytes.len() > MAX_MESSAGE {
            return Err(Error::InvalidMessage);
        }
        Ok(Self { bytes, position: 0 })
    }

    pub fn write(bytes: &'a mut [u8], overhead: usize, payload_len: usize) -> Result<Self, Error> {
        let length = overhead
            .checked_add(payload_len)
            .ok_or(Error::MessageTooLong)?;
        if length > MAX_MESSAGE {
            return Err(Error::MessageTooLong);
        }
        if bytes.len() < length {
            return Err(Error::BufferTooSmall);
        }
        Ok(Self {
            bytes: &mut bytes[..length],
            position: 0,
        })
    }

    pub fn take(&mut self, length: usize) -> Result<&mut [u8], Error> {
        let start = self.position;
        let end = start.checked_add(length).ok_or(Error::InvalidMessage)?;
        let field = self
            .bytes
            .get_mut(start..end)
            .ok_or(Error::InvalidMessage)?;
        self.position = end;
        Ok(field)
    }

    pub fn write_e<C: Crypto, M: PskMode>(&mut self, core: &mut Core<C>) -> Result<(), Error> {
        core.generate()?;
        // SAFETY: generate just installed the local ephemeral keypair.
        let public = unsafe { &present(&core.e).public };
        let field = self.take(C::Dh::PUBLIC_KEY_LEN)?;
        field.copy_from_slice(public.as_ref());
        core.mix_hash(field);
        if M::ENABLED {
            core.mix_key(field)?;
        }
        Ok(())
    }

    pub fn read_e<C: Crypto, M: PskMode>(&mut self, core: &mut Core<C>) -> Result<(), Error> {
        let field = self.take(C::Dh::PUBLIC_KEY_LEN)?;
        core.re = Some(C::Dh::parse_public(field)?);
        core.mix_hash(field);
        if M::ENABLED {
            core.mix_key(field)?;
        }
        Ok(())
    }

    /// # Safety
    /// The local static public key and handshake cipher key must be present.
    pub unsafe fn write_s<C: Crypto>(&mut self, core: &mut Core<C>) -> Result<(), Error> {
        let field = self.take(C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN)?;
        // SAFETY: inherited from this method's contract.
        field[..C::Dh::PUBLIC_KEY_LEN].copy_from_slice(unsafe { present(&core.s) }.as_ref());
        // SAFETY: inherited from this method's contract.
        unsafe { core.encrypt(field) }
    }

    /// # Safety
    /// The handshake cipher key must be present.
    pub unsafe fn read_s<C: Crypto>(&mut self, core: &mut Core<C>) -> Result<(), Error> {
        let field = self.take(C::Dh::PUBLIC_KEY_LEN + C::Cipher::TAG_LEN)?;
        // SAFETY: inherited from this method's contract.
        let public = unsafe { core.decrypt(field)? };
        core.rs = Some(C::Dh::parse_public(public)?);
        Ok(())
    }

    /// # Safety
    /// The handshake cipher key must be present.
    pub unsafe fn encrypt_payload<C: Crypto>(
        self,
        core: &mut Core<C>,
    ) -> Result<&'a mut [u8], Error> {
        // SAFETY: inherited from this method's contract.
        unsafe {
            core.encrypt(&mut self.bytes[self.position..])?;
        }
        Ok(self.bytes)
    }

    /// # Safety
    /// The handshake cipher key must be present.
    pub unsafe fn decrypt_payload<C: Crypto>(
        self,
        core: &mut Core<C>,
    ) -> Result<&'a mut [u8], Error> {
        // SAFETY: inherited from this method's contract.
        unsafe { core.decrypt(&mut self.bytes[self.position..]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DefaultCrypto;

    #[test]
    fn nonce_limit_is_checked_before_reuse() {
        let mut sending = CipherState::<DefaultCrypto>::empty();
        let mut receiving = CipherState::<DefaultCrypto>::empty();
        sending.set_key([7; 32]);
        receiving.set_key([7; 32]);
        sending.nonce = u64::MAX - 1;
        receiving.nonce = u64::MAX - 1;
        let mut message = [0; 16];
        // SAFETY: both keys were installed above.
        unsafe {
            sending.encrypt(&[], &mut message).unwrap();
            receiving.decrypt(&[], &mut message).unwrap();
            assert_eq!(
                sending.encrypt(&[], &mut message),
                Err(Error::NonceExhausted)
            );
            assert_eq!(
                receiving.decrypt(&[], &mut message),
                Err(Error::NonceExhausted)
            );
        }
        assert_eq!(sending.nonce, u64::MAX);
        assert_eq!(receiving.nonce, u64::MAX);
    }
}
