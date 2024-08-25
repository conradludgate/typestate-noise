#![allow(clippy::type_complexity)]

use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

pub struct HList<T, U>(T, U);

#[macro_export]
macro_rules! hlist {
    [$t0:ty $(,)?] => {
        $t0
    };
    [$t0:ty $(, $t:ty)* $(,)?] => {
        $crate::HList<$t0, $crate::hlist![$($t),*]>
    };
}

impl<K0, K1, K2, K3, K4, S, T, U> Send<K0, K1, K2, K3, K4, S> for HList<T, U>
where
    K0: Val,
    K1: Val,
    K2: Val,
    K3: Val,
    K4: Val,
    S: Sender,

    T: Send<K0, K1, K2, K3, K4, S>,
    U: Send<T::K0, T::K1, T::K2, T::K3, T::K4, S>,
{
    type K0 = U::K0;
    type K1 = U::K1;
    type K2 = U::K2;
    type K3 = U::K3;
    type K4 = U::K4;

    fn send(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, K1, K2, K3, K4>,
        sender: S,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let state = T::send(b, state, sender);
        U::send(b, state, sender)
    }
}

impl<K0, K1, K2, K3, K4, S, T, U> Recv<K0, K1, K2, K3, K4, S> for HList<T, U>
where
    K0: Val,
    K1: Val,
    K2: Val,
    K3: Val,
    K4: Val,
    S: Sender,

    T: Recv<K0, K1, K2, K3, K4, S>,
    U: Recv<T::K0, T::K1, T::K2, T::K3, T::K4, S>,
{
    type K0 = U::K0;
    type K1 = U::K1;
    type K2 = U::K2;
    type K3 = U::K3;
    type K4 = U::K4;

    fn recv(
        b: &mut BytesMut,
        state: HandshakeState<K0, K1, K2, K3, K4>,
        sender: S,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let state = T::recv(b, state, sender)?;
        U::recv(b, state, sender)
    }
}

/// Appends "EncryptAndHash(s.public_key)" to the buffer.
pub struct S;

impl<K0: Val, K1: Val, K3: Val, K4: Val, S_> Recv<K0, K1, Unknown, K3, K4, S_> for S
where
    CipherState<K4>: CipherStateAlg,
    S_: Sender,
{
    type K0 = K0;
    type K1 = K1;
    type K2 = Known;
    type K3 = K3;
    type K4 = K4;

    fn recv(
        b: &mut BytesMut,
        mut state: HandshakeState<K0, K1, Unknown, K3, K4>,
        _sender: S_,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        // typecheck that rs is unknown
        let _: Unknown = state.rs;

        if b.len() < 32 + state.cipher.tag_len() {
            return Err(chacha20poly1305::Error);
        }
        let mut payload = b.split_to(32 + state.cipher.tag_len());
        let pk = state
            .symm
            .decrypt_and_hash(&mut payload, &mut state.cipher)?;
        let pk = PublicKey::from(<[u8; 32]>::try_from(pk).unwrap());

        Ok(HandshakeState::<K0, K1, Known, K3, K4> {
            cipher: state.cipher,
            symm: state.symm,
            s: state.s,
            e: state.e,
            rs: PubKey(pk),
            re: state.re,
        })
    }
}

impl<K1: Val, K2: Val, K3: Val, K4: Val, S_> Send<Known, K1, K2, K3, K4, S_> for S
where
    CipherState<K4>: CipherStateAlg,
    S_: Sender,
{
    type K0 = Known;
    type K1 = K1;
    type K2 = K2;
    type K3 = K3;
    type K4 = K4;

    fn send(
        b: &mut Vec<u8>,
        mut state: HandshakeState<Known, K1, K2, K3, K4>,
        _sender: S_,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let pk = PublicKey::from(&state.s.0);
        state
            .symm
            .encrypt_and_hash(pk.as_bytes(), b, &mut state.cipher);
        state
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct E;

impl<K0: Val, K1: Val, K2: Val, K4: Val, S> Recv<K0, K1, K2, Unknown, K4, S> for E
where
    S: Sender,
{
    type K0 = K0;
    type K1 = K1;
    type K2 = K2;
    type K3 = Known;
    type K4 = K4;

    fn recv(
        b: &mut BytesMut,
        mut state: HandshakeState<K0, K1, K2, Unknown, K4>,
        _sender: S,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        // typecheck that re is unknown
        let _: Unknown = state.re;

        if b.len() < 32 {
            return Err(chacha20poly1305::Error);
        }
        let payload = b.split_to(32);
        state.symm = state.symm.mix_hash(&payload);
        let pk = PublicKey::from(<[u8; 32]>::try_from(&*payload).unwrap());

        Ok(HandshakeState::<K0, K1, K2, Known, K4> {
            cipher: state.cipher,
            symm: state.symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: PubKey(pk),
        })
    }
}

impl<K0: Val, K2: Val, K3: Val, K4: Val, S> Send<K0, Unknown, K2, K3, K4, S> for E
where
    S: Sender,
{
    type K0 = K0;
    type K1 = Known;
    type K2 = K2;
    type K3 = K3;
    type K4 = K4;

    fn send(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, Unknown, K2, K3, K4>,
        _sender: S,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let ek = ReusableSecret::random();
        let pk = PublicKey::from(&ek);
        b.extend_from_slice(pk.as_bytes());
        let symm = state.symm.mix_hash(pk.as_bytes());

        HandshakeState::<K0, Known, K2, K3, K4> {
            cipher: state.cipher,
            symm,
            s: state.s,
            e: EphKeyPair(ek),
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct Ee;

impl<K0: Val, K2: Val, K4: Val, S> Recv<K0, Known, K2, Known, K4, S> for Ee
where
    S: Sender,
{
    type K0 = K0;
    type K1 = Known;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<K0, Known, K2, Known, K4>,
        _sender: S,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.e.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<K0, Known, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K0: Val, K2: Val, K4: Val, S> Send<K0, Known, K2, Known, K4, S> for Ee
where
    S: Sender,
{
    type K0 = K0;
    type K1 = Known;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, K2, Known, K4>,
        _sender: S,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.e.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<K0, Known, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Calls MixKey(DH(s, rs)).
pub struct Ss;

impl<K1: Val, K3: Val, K4: Val, S> Recv<Known, K1, Known, K3, K4, S> for Ss
where
    S: Sender,
{
    type K0 = Known;
    type K1 = K1;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<Known, K1, Known, K3, K4>,
        _sender: S,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.s.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Known, K1, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K1: Val, K3: Val, K4: Val, S> Send<Known, K1, Known, K3, K4, S> for Ss
where
    S: Sender,
{
    type K0 = Known;
    type K1 = K1;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, Known, K3, K4>,
        _sender: S,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.s.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Known, K1, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
pub struct Es;

impl<K0: Val, K3: Val, K4: Val> Recv<K0, Known, Known, K3, K4, Initiator> for Es {
    type K0 = K0;
    type K1 = Known;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<K0, Known, Known, K3, K4>,
        _sender: Initiator,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<K0, Known, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K0: Val, K3: Val, K4: Val> Send<K0, Known, Known, K3, K4, Initiator> for Es {
    type K0 = K0;
    type K1 = Known;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, Known, K3, K4>,
        _sender: Initiator,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<K0, Known, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

impl<K1: Val, K2: Val, K4: Val> Recv<Known, K1, K2, Known, K4, Responder> for Es {
    type K0 = Known;
    type K1 = K1;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<Known, K1, K2, Known, K4>,
        _sender: Responder,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Known, K1, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K1: Val, K2: Val, K4: Val> Send<Known, K1, K2, Known, K4, Responder> for Es {
    type K0 = Known;
    type K1 = K1;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, K2, Known, K4>,
        _sender: Responder,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Known, K1, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
pub struct Se;

impl<K0: Val, K3: Val, K4: Val> Recv<K0, Known, Known, K3, K4, Responder> for Se {
    type K0 = K0;
    type K1 = Known;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<K0, Known, Known, K3, K4>,
        _sender: Responder,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<K0, Known, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K0: Val, K3: Val, K4: Val> Send<K0, Known, Known, K3, K4, Responder> for Se {
    type K0 = K0;
    type K1 = Known;
    type K2 = Known;
    type K3 = K3;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, Known, K3, K4>,
        _sender: Responder,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<K0, Known, Known, K3, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

impl<K1: Val, K2: Val, K4: Val> Recv<Known, K1, K2, Known, K4, Initiator> for Se {
    type K0 = Known;
    type K1 = K1;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<Known, K1, K2, Known, K4>,
        _sender: Initiator,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Known, K1, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K1: Val, K2: Val, K4: Val> Send<Known, K1, K2, Known, K4, Initiator> for Se {
    type K0 = Known;
    type K1 = K1;
    type K2 = K2;
    type K3 = Known;
    type K4 = Known;

    fn send(
        _b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, K2, Known, K4>,
        _sender: Initiator,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Known, K1, K2, Known, Known> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

pub trait Send<K0: Val, K1: Val, K2: Val, K3: Val, K4: Val, S>
where
    S: Sender,
{
    type K0: Val;
    type K1: Val;
    type K2: Val;
    type K3: Val;
    type K4: Val;

    fn send(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, K1, K2, K3, K4>,
        _sender: S,
    ) -> HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>;
}

pub type Error = chacha20poly1305::Error;

pub trait Recv<K0: Val, K1: Val, K2: Val, K3: Val, K4: Val, S>
where
    S: Sender,
{
    type K0: Val;
    type K1: Val;
    type K2: Val;
    type K3: Val;
    type K4: Val;

    fn recv(
        b: &mut BytesMut,
        state: HandshakeState<K0, K1, K2, K3, K4>,
        _sender: S,
    ) -> Result<HandshakeState<Self::K0, Self::K1, Self::K2, Self::K3, Self::K4>, Error>;
}

pub trait Sender: Copy {}
#[derive(Clone, Copy)]
pub struct Initiator;
#[derive(Clone, Copy)]
pub struct Responder;

impl Sender for Initiator {}
impl Sender for Responder {}

pub trait Val {
    type Val<T>;
}
pub struct Known;
pub struct Unknown;

impl Val for Known {
    type Val<T> = T;
}

impl Val for Unknown {
    type Val<T> = Unknown;
}

pub struct EphKeyPair(ReusableSecret);
pub struct KeyPair(StaticSecret);
pub struct PubKey(PublicKey);
pub struct Key(chacha20poly1305::Key);

pub trait CipherStateAlg {
    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8], ciphertext: &mut Vec<u8>);
    fn decrypt_with_ad<'a>(
        &mut self,
        ad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], chacha20poly1305::Error>;
    fn has_key(&self) -> bool;
    fn tag_len(&self) -> usize;
}

impl CipherStateAlg for CipherState<Known> {
    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8], ciphertext: &mut Vec<u8>) {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        let l = ciphertext.len();
        ciphertext.extend_from_slice(plaintext);

        let n = self.n;

        let tag = ChaCha20Poly1305::new(&self.k.0)
            .encrypt_in_place_detached(&nonce(n), ad, &mut ciphertext[l..])
            .unwrap();

        self.n += 1;
        ciphertext.extend_from_slice(&tag);
    }

    fn decrypt_with_ad<'a>(
        &mut self,
        ad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], chacha20poly1305::Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        let (plaintext, tag) = ciphertext
            .split_at_mut_checked(ciphertext.len() - 16)
            .ok_or(chacha20poly1305::Error)?;
        let tag = Tag::from_slice(tag);

        let n = self.n;

        ChaCha20Poly1305::new(&self.k.0).decrypt_in_place_detached(
            &nonce(n),
            ad,
            plaintext,
            tag,
        )?;

        self.n += 1;

        Ok(plaintext)
    }

    fn has_key(&self) -> bool {
        true
    }

    fn tag_len(&self) -> usize {
        16
    }
}

impl CipherStateAlg for CipherState<Unknown> {
    fn encrypt_with_ad(&mut self, _ad: &[u8], plaintext: &[u8], ciphertext: &mut Vec<u8>) {
        ciphertext.extend_from_slice(plaintext);
    }

    fn decrypt_with_ad<'a>(
        &mut self,
        _ad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], chacha20poly1305::Error> {
        Ok(ciphertext)
    }

    fn has_key(&self) -> bool {
        false
    }

    fn tag_len(&self) -> usize {
        0
    }
}

fn nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut n = chacha20poly1305::Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

impl SymmetricState {
    fn mix_hash(&self, data: &[u8]) -> Self {
        use sha2::Digest;
        let h = Sha256::new()
            .chain_update(self.h)
            .chain_update(data)
            .finalize()
            .into();
        Self { ck: self.ck, h }
    }

    fn mix_hash_and_key(&self, data: &[u8]) -> (Self, CipherState<Known>) {
        let [ck, temp_h, temp_k] = hkdf(&self.ck, data);
        let mut this = self.mix_hash(&temp_h);
        this.ck = ck;
        (
            this,
            CipherState {
                k: Key(temp_k.into()),
                n: 0,
            },
        )
    }

    fn mix_key(&self, data: &[u8]) -> (Self, CipherState<Known>) {
        let [ck, temp_k] = hkdf(&self.ck, data);
        (
            Self { ck, h: self.h },
            CipherState {
                k: Key(temp_k.into()),
                n: 0,
            },
        )
    }

    fn mix_chain_key(&self, data: &[u8]) -> Self {
        let [ck] = hkdf(&self.ck, data);
        Self { ck, h: self.h }
    }

    fn encrypt_and_hash<K>(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
        c: &mut CipherState<K>,
    ) where
        K: Val,
        CipherState<K>: CipherStateAlg,
    {
        let l = ciphertext.len();
        c.encrypt_with_ad(&self.h, plaintext, ciphertext);
        *self = self.mix_hash(&ciphertext[l..]);
    }

    fn decrypt_and_hash<'a, K>(
        &mut self,
        ciphertext: &'a mut [u8],
        c: &mut CipherState<K>,
    ) -> Result<&'a mut [u8], chacha20poly1305::Error>
    where
        K: Val,
        CipherState<K>: CipherStateAlg,
    {
        let new = self.mix_hash(ciphertext);
        let p = c.decrypt_with_ad(&self.h, ciphertext)?;
        *self = new;

        Ok(p)
    }
}

fn hkdf<const N: usize>(key: &[u8; 32], msg: &[u8]) -> [[u8; 32]; N] {
    use hmac::Mac;
    type Hmac = hmac::Hmac<Sha256>;

    assert!(N > 0);
    assert!(N <= 255);

    let mut output = [[0u8; 32]; N];

    let tk = Hmac::new_from_slice(key)
        .unwrap()
        .chain_update(msg)
        .finalize()
        .into_bytes();
    let hmac = Hmac::new_from_slice(&tk).unwrap();
    let mut ti = hmac.clone().chain_update([1u8]).finalize().into_bytes();
    output[0] = ti.into();

    for i in 1..N as u8 {
        ti = hmac
            .clone()
            .chain_update(ti)
            .chain_update([i + 1])
            .finalize()
            .into_bytes();
        output[i as usize] = ti.into();
    }

    output
}

pub struct CipherState<K>
where
    K: Val,
{
    /// cipher key
    k: K::Val<Key>,
    /// nonce
    n: u64,
}

pub struct SymmetricState {
    /// chaining key
    ck: [u8; 32],
    /// hash
    h: [u8; 32],
}

pub struct HandshakeState<K0, K1, K2, K3, K4>
where
    K0: Val,
    K1: Val,
    K2: Val,
    K3: Val,
    K4: Val,
{
    cipher: CipherState<K4>,
    symm: SymmetricState,

    /// local static key pair
    s: K0::Val<KeyPair>,
    /// local ephemeral key pair
    e: K1::Val<EphKeyPair>,
    /// remote static public key
    rs: K2::Val<PubKey>,
    /// remote ephemeral public key
    re: K3::Val<PubKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    type IkPre0 = hlist![S];
    type IkMsg0 = hlist![E, Es, S, Ss];
    type IkMsg1 = hlist![E, Ee, Se];

    #[test]
    fn check_ik_pre0() {
        IkPre0::send(
            &mut vec![],
            HandshakeState::<Known, Unknown, Unknown, Unknown, Unknown> {
                cipher: CipherState { k: Unknown, n: 0 },
                symm: SymmetricState {
                    h: [0; 32],
                    ck: [0; 32],
                },
                s: KeyPair(StaticSecret::random()),
                e: Unknown,
                rs: Unknown,
                re: Unknown,
            },
            Responder,
        );
    }

    #[test]
    fn check_ik_msg0() {
        let sk = StaticSecret::random();

        IkMsg0::send(
            &mut vec![],
            HandshakeState::<Known, Unknown, Known, Unknown, Unknown> {
                cipher: CipherState { k: Unknown, n: 0 },
                symm: SymmetricState {
                    h: [0; 32],
                    ck: [0; 32],
                },
                s: KeyPair(StaticSecret::random()),
                e: Unknown,
                rs: PubKey(PublicKey::from(&sk)),
                re: Unknown,
            },
            Initiator,
        );
    }

    #[test]
    fn check_ik_msg1() {
        let ek = ReusableSecret::random();
        let sk = StaticSecret::random();

        IkMsg1::send(
            &mut vec![],
            HandshakeState::<Known, Unknown, Known, Known, Known> {
                cipher: CipherState {
                    k: Key(Default::default()),
                    n: 0,
                },
                symm: SymmetricState {
                    h: [0; 32],
                    ck: [0; 32],
                },
                s: KeyPair(StaticSecret::random()),
                e: Unknown,
                rs: PubKey(PublicKey::from(&sk)),
                re: PubKey(PublicKey::from(&ek)),
            },
            Responder,
        );
    }
}
