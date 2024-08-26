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

impl<T, U, St: States + ?Sized> SendPreMsg<St> for HList<T, U>
where
    T: SendPreMsg<St>,
    U: SendPreMsg<T::St>,
{
    type St = U::St;

    fn send_premsg(b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<U::St> {
        let state = T::send_premsg(b, state);
        U::send_premsg(b, state)
    }
}

impl<T, U, St: States + ?Sized> RecvPreMsg<St> for HList<T, U>
where
    T: RecvPreMsg<St>,
    U: RecvPreMsg<T::St>,
{
    type St = U::St;

    fn recv_premsg(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let state = T::recv_premsg(b, state)?;
        U::recv_premsg(b, state)
    }
}

impl<T, U, St: States + ?Sized> SendWithPayload<St> for HList<T, U>
where
    T: Send<St>,
    U: SendWithPayload<T::St>,
{
    type St = U::St;

    fn send_with_payload(
        b: &mut BytesMut,
        state: HandshakeState<St>,
        payload: &[u8],
    ) -> HandshakeState<U::St> {
        let state = T::send(b, state);
        U::send_with_payload(b, state, payload)
    }
}

impl<T, U, St: States + ?Sized> RecvWithPayload<St> for HList<T, U>
where
    T: Recv<St>,
    U: RecvWithPayload<T::St>,
{
    type St = U::St;

    fn recv_with_payload(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<(HandshakeState<Self::St>, BytesMut), Error> {
        let state = T::recv(b, state)?;
        U::recv_with_payload(b, state)
    }
}

pub struct Payload;

impl<St: States + ?Sized> SendWithPayload<St> for Payload
where
    CipherState<St::EncryptionKey>: CipherStateAlg,
{
    type St = St;

    fn send_with_payload(
        b: &mut BytesMut,
        mut state: HandshakeState<St>,
        payload: &[u8],
    ) -> HandshakeState<Self::St> {
        state.symm.encrypt_and_hash(payload, b, &mut state.cipher);
        state
    }
}

impl<St: States + ?Sized> RecvWithPayload<St> for Payload
where
    CipherState<St::EncryptionKey>: CipherStateAlg,
{
    type St = St;

    fn recv_with_payload(
        b: &mut BytesMut,
        mut state: HandshakeState<St>,
    ) -> Result<(HandshakeState<Self::St>, BytesMut), Error> {
        let b = state.symm.decrypt_and_hash(b.split(), &mut state.cipher)?;
        Ok((state, b))
    }
}

/// Appends "EncryptAndHash(s.public_key)" to the buffer.
pub struct S;

impl<St: States<RemoteStaticKey = Unknown> + ?Sized> Recv<St> for S
where
    CipherState<St::EncryptionKey>: CipherStateAlg,
{
    type St = <St as StatesExt>::WithRemoteStaticKey;

    fn recv(
        b: &mut BytesMut,
        mut state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        // typecheck that rs is unknown
        let _: Unknown = state.rs;

        if b.len() < 32 + state.cipher.tag_len() {
            return Err(chacha20poly1305::Error);
        }
        let payload = b.split_to(32 + state.cipher.tag_len());
        let pk = state.symm.decrypt_and_hash(payload, &mut state.cipher)?;
        let pk = PublicKey::from(<[u8; 32]>::try_from(&*pk).unwrap());

        Ok(HandshakeState::<Self::St> {
            cipher: state.cipher,
            symm: state.symm,
            s: state.s,
            e: state.e,
            rs: PubKey(pk),
            re: state.re,
        })
    }
}

impl<St: States<StaticKey = Known> + ?Sized> Send<St> for S
where
    CipherState<St::EncryptionKey>: CipherStateAlg,
{
    type St = St;

    fn send(b: &mut BytesMut, mut state: HandshakeState<St>) -> HandshakeState<St> {
        let pk = PublicKey::from(&state.s.0).to_bytes();
        state.symm.encrypt_and_hash(&pk, b, &mut state.cipher);
        state
    }
}

impl<St: States<RemoteStaticKey = Unknown, EncryptionKey = Unknown> + ?Sized> RecvPreMsg<St> for S {
    type St = <St as StatesExt>::WithRemoteStaticKey;

    fn recv_premsg(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        if b.len() < 32 + state.cipher.tag_len() {
            return Err(chacha20poly1305::Error);
        }
        let payload = b.split_to(32);
        state.symm.mix_hash(&payload);
        let pk = PublicKey::from(<[u8; 32]>::try_from(&*payload).unwrap());

        Ok(HandshakeState::<Self::St> {
            cipher: state.cipher,
            symm: state.symm,
            s: state.s,
            e: state.e,
            rs: PubKey(pk),
            re: state.re,
        })
    }
}

impl<St: States<StaticKey = Known, EncryptionKey = Unknown> + ?Sized> SendPreMsg<St> for S {
    type St = St;

    fn send_premsg(b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<St> {
        let pk = PublicKey::from(&state.s.0).to_bytes();
        b.extend_from_slice(&pk);
        state.symm.mix_hash(&pk);
        state
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct E;

impl<St: States<RemoteEphemeralKey = Unknown> + ?Sized> Recv<St> for E
where
    CipherState<St::EncryptionKey>: CipherStateAlg,
{
    type St = <St as StatesExt>::WithRemoteEphemeralKey;

    fn recv(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        // typecheck that re is unknown
        let _: Unknown = state.re;

        if b.len() < 32 {
            return Err(chacha20poly1305::Error);
        }
        let payload = b.split_to(32);
        let symm = state.symm.mix_hash(&payload);
        let pk = PublicKey::from(<[u8; 32]>::try_from(&*payload).unwrap());

        Ok(HandshakeState::<Self::St> {
            cipher: state.cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: PubKey(pk),
        })
    }
}

impl<St: States<EphemeralKey = Unknown> + ?Sized> Send<St> for E {
    type St = <St as StatesExt>::WithEphemeralKey;

    fn send(b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St> {
        #[cfg(unsafe_typestate_noise_vectors)]
        let ek = StaticSecret::random();
        #[cfg(not(unsafe_typestate_noise_vectors))]
        let ek = ReusableSecret::random();

        let pk = PublicKey::from(&ek);
        b.extend_from_slice(pk.as_bytes());
        let symm = state.symm.mix_hash(pk.as_bytes());

        HandshakeState::<Self::St> {
            cipher: state.cipher,
            symm,
            s: state.s,
            e: EphKeyPair(ek),
            rs: state.rs,
            re: state.re,
        }
    }
}

#[cfg(unsafe_typestate_noise_vectors)]
type ETest<K0, K2, K3, K4, S> = dyn States<
    StaticKey = K0,
    EphemeralKey = Known,
    RemoteStaticKey = K2,
    RemoteEphemeralKey = K3,
    EncryptionKey = K4,
    Side = S,
>;

#[cfg(unsafe_typestate_noise_vectors)]
impl<K0: Val, K2: Val, K3: Val, K4: Val, S: Sender> Send<ETest<K0, K2, K3, K4, S>> for E {
    type St = ETest<K0, K2, K3, K4, S>;

    fn send(
        b: &mut BytesMut,
        state: HandshakeState<ETest<K0, K2, K3, K4, S>>,
    ) -> HandshakeState<Self::St> {
        let pk = PublicKey::from(&state.e.0);
        b.extend_from_slice(pk.as_bytes());
        let symm = state.symm.mix_hash(pk.as_bytes());

        HandshakeState::<Self::St> {
            cipher: state.cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct Ee;

impl<St: States<EphemeralKey = Known, RemoteEphemeralKey = Known> + ?Sized> Recv<St> for Ee {
    type St = <St as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.e.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<St: States<EphemeralKey = Known, RemoteEphemeralKey = Known> + ?Sized> Send<St> for Ee {
    type St = <St as StatesExt>::WithEncryptionKey;

    fn send(_b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St> {
        let dh = state.e.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Self::St> {
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

impl<St: States<StaticKey = Known, RemoteStaticKey = Known> + ?Sized> Recv<St> for Ss {
    type St = <St as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.s.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<St: States<StaticKey = Known, RemoteStaticKey = Known> + ?Sized> Send<St> for Ss {
    type St = <St as StatesExt>::WithEncryptionKey;

    fn send(_b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St> {
        let dh = state.s.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Self::St> {
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

impl<St: States<EphemeralKey = Known, RemoteStaticKey = Known, Side = Initiator> + ?Sized> Recv<St>
    for Es
{
    type St = <St as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<St: States<EphemeralKey = Known, RemoteStaticKey = Known, Side = Initiator> + ?Sized> Send<St>
    for Es
{
    type St = <St as StatesExt>::WithEncryptionKey;

    fn send(_b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

type EsResp<K1, K2, K4> = dyn States<
    StaticKey = Known,
    EphemeralKey = K1,
    RemoteStaticKey = K2,
    RemoteEphemeralKey = Known,
    EncryptionKey = K4,
    Side = Responder,
>;

impl<K1: Val, K2: Val, K4: Val> Recv<EsResp<K1, K2, K4>> for Es {
    type St = <EsResp<K1, K2, K4> as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<EsResp<K1, K2, K4>>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K1: Val, K2: Val, K4: Val> Send<EsResp<K1, K2, K4>> for Es {
    type St = <EsResp<K1, K2, K4> as StatesExt>::WithEncryptionKey;

    fn send(
        _b: &mut BytesMut,
        state: HandshakeState<EsResp<K1, K2, K4>>,
    ) -> HandshakeState<Self::St> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Self::St> {
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

type SeResp<K0, K3, K4> = dyn States<
    StaticKey = K0,
    EphemeralKey = Known,
    RemoteStaticKey = Known,
    RemoteEphemeralKey = K3,
    EncryptionKey = K4,
    Side = Responder,
>;

impl<K0: Val, K3: Val, K4: Val> Recv<SeResp<K0, K3, K4>> for Se {
    type St = <SeResp<K0, K3, K4> as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<SeResp<K0, K3, K4>>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K0: Val, K3: Val, K4: Val> Send<SeResp<K0, K3, K4>> for Se {
    type St = <SeResp<K0, K3, K4> as StatesExt>::WithEncryptionKey;

    fn send(
        _b: &mut BytesMut,
        state: HandshakeState<SeResp<K0, K3, K4>>,
    ) -> HandshakeState<Self::St> {
        let dh = state.e.0.diffie_hellman(&state.rs.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState::<Self::St> {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

type EsInit<K1, K2, K4> = dyn States<
    StaticKey = Known,
    EphemeralKey = K1,
    RemoteStaticKey = K2,
    RemoteEphemeralKey = Known,
    EncryptionKey = K4,
    Side = Initiator,
>;

impl<K1: Val, K2: Val, K4: Val> Recv<EsInit<K1, K2, K4>> for Se {
    type St = <EsInit<K1, K2, K4> as StatesExt>::WithEncryptionKey;

    fn recv(
        _b: &mut BytesMut,
        state: HandshakeState<EsInit<K1, K2, K4>>,
    ) -> Result<HandshakeState<Self::St>, Error> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        Ok(HandshakeState {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        })
    }
}

impl<K1: Val, K2: Val, K4: Val> Send<EsInit<K1, K2, K4>> for Se {
    type St = <EsInit<K1, K2, K4> as StatesExt>::WithEncryptionKey;

    fn send(
        _b: &mut BytesMut,
        state: HandshakeState<EsInit<K1, K2, K4>>,
    ) -> HandshakeState<Self::St> {
        let dh = state.s.0.diffie_hellman(&state.re.0);
        let (symm, cipher) = state.symm.mix_key(dh.as_bytes());

        HandshakeState {
            cipher,
            symm,
            s: state.s,
            e: state.e,
            rs: state.rs,
            re: state.re,
        }
    }
}

pub trait States {
    type StaticKey: Val;
    type EphemeralKey: Val;
    type RemoteStaticKey: Val;
    type RemoteEphemeralKey: Val;
    type EncryptionKey: Val;
    type Side: Sender;
}

pub trait StatesExt {
    type WithStaticKey: States + ?Sized;
    type WithEphemeralKey: States + ?Sized;
    type WithRemoteStaticKey: States + ?Sized;
    type WithRemoteEphemeralKey: States + ?Sized;
    type WithEncryptionKey: States + ?Sized;
}

impl<St: States + ?Sized> StatesExt for St {
    type WithStaticKey = dyn States<
        StaticKey = Known,
        EphemeralKey = St::EphemeralKey,
        RemoteStaticKey = St::RemoteStaticKey,
        RemoteEphemeralKey = St::RemoteEphemeralKey,
        EncryptionKey = St::EncryptionKey,
        Side = St::Side,
    >;
    type WithEphemeralKey = dyn States<
        StaticKey = St::StaticKey,
        EphemeralKey = Known,
        RemoteStaticKey = St::RemoteStaticKey,
        RemoteEphemeralKey = St::RemoteEphemeralKey,
        EncryptionKey = St::EncryptionKey,
        Side = St::Side,
    >;
    type WithRemoteStaticKey = dyn States<
        StaticKey = St::StaticKey,
        EphemeralKey = St::EphemeralKey,
        RemoteStaticKey = Known,
        RemoteEphemeralKey = St::RemoteEphemeralKey,
        EncryptionKey = St::EncryptionKey,
        Side = St::Side,
    >;
    type WithRemoteEphemeralKey = dyn States<
        StaticKey = St::StaticKey,
        EphemeralKey = St::EphemeralKey,
        RemoteStaticKey = St::RemoteStaticKey,
        RemoteEphemeralKey = Known,
        EncryptionKey = St::EncryptionKey,
        Side = St::Side,
    >;
    type WithEncryptionKey = dyn States<
        StaticKey = St::StaticKey,
        EphemeralKey = St::EphemeralKey,
        RemoteStaticKey = St::RemoteStaticKey,
        RemoteEphemeralKey = St::RemoteEphemeralKey,
        EncryptionKey = Known,
        Side = St::Side,
    >;
}

pub trait Send<St: States + ?Sized> {
    type St: States + ?Sized;

    fn send(b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St>;
}

pub trait SendPreMsg<St: States + ?Sized> {
    type St: States + ?Sized;

    fn send_premsg(b: &mut BytesMut, state: HandshakeState<St>) -> HandshakeState<Self::St>;
}

pub trait SendWithPayload<St: States + ?Sized> {
    type St: States + ?Sized;

    fn send_with_payload(
        b: &mut BytesMut,
        state: HandshakeState<St>,
        payload: &[u8],
    ) -> HandshakeState<Self::St>;
}

pub type Error = chacha20poly1305::Error;

pub trait Recv<St: States + ?Sized> {
    type St: States + ?Sized;

    fn recv(b: &mut BytesMut, state: HandshakeState<St>)
        -> Result<HandshakeState<Self::St>, Error>;
}

pub trait RecvPreMsg<St: States + ?Sized> {
    type St: States + ?Sized;

    fn recv_premsg(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<HandshakeState<Self::St>, Error>;
}

pub trait RecvWithPayload<St: States + ?Sized> {
    type St: States + ?Sized;

    fn recv_with_payload(
        b: &mut BytesMut,
        state: HandshakeState<St>,
    ) -> Result<(HandshakeState<Self::St>, BytesMut), Error>;
}

pub trait Sender {}
pub struct Initiator;
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
#[cfg(not(unsafe_typestate_noise_vectors))]
pub struct EphKeyPair(ReusableSecret);
#[cfg(unsafe_typestate_noise_vectors)]
pub struct EphKeyPair(StaticSecret);
pub struct KeyPair(StaticSecret);
pub struct PubKey(PublicKey);
pub struct Key(pub chacha20poly1305::Key);

pub trait CipherStateAlg {
    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8], ciphertext: &mut BytesMut);
    fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: BytesMut,
    ) -> Result<BytesMut, chacha20poly1305::Error>;
    fn has_key(&self) -> bool;
    fn tag_len(&self) -> usize;
}

impl CipherStateAlg for CipherState<Known> {
    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8], ciphertext: &mut BytesMut) {
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

    fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        mut ciphertext: BytesMut,
    ) -> Result<BytesMut, chacha20poly1305::Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        if ciphertext.len() < 16 {
            return Err(chacha20poly1305::Error);
        }
        let tag = ciphertext.split_off(ciphertext.len() - 16);
        let tag = Tag::from_slice(&tag);

        let n = self.n;

        ChaCha20Poly1305::new(&self.k.0).decrypt_in_place_detached(
            &nonce(n),
            ad,
            &mut ciphertext,
            tag,
        )?;

        self.n += 1;

        Ok(ciphertext)
    }

    fn has_key(&self) -> bool {
        true
    }

    fn tag_len(&self) -> usize {
        16
    }
}

impl CipherStateAlg for CipherState<Unknown> {
    fn encrypt_with_ad(&mut self, _ad: &[u8], plaintext: &[u8], ciphertext: &mut BytesMut) {
        ciphertext.extend_from_slice(plaintext);
    }

    fn decrypt_with_ad(
        &mut self,
        _ad: &[u8],
        ciphertext: BytesMut,
    ) -> Result<BytesMut, chacha20poly1305::Error> {
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
        ciphertext: &mut BytesMut,
        c: &mut CipherState<K>,
    ) where
        K: Val,
        CipherState<K>: CipherStateAlg,
    {
        let l = ciphertext.len();
        c.encrypt_with_ad(&self.h, plaintext, ciphertext);
        *self = self.mix_hash(&ciphertext[l..]);
    }

    fn decrypt_and_hash<K>(
        &mut self,
        ciphertext: BytesMut,
        c: &mut CipherState<K>,
    ) -> Result<BytesMut, chacha20poly1305::Error>
    where
        K: Val,
        CipherState<K>: CipherStateAlg,
    {
        let new = self.mix_hash(&ciphertext);
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
    pub k: K::Val<Key>,
    /// nonce
    pub n: u64,
}

impl Default for CipherState<Unknown> {
    fn default() -> Self {
        Self { k: Unknown, n: 0 }
    }
}

pub struct SymmetricState {
    /// chaining key
    pub ck: [u8; 32],
    /// hash
    pub h: [u8; 32],
}

impl SymmetricState {
    pub fn new(protocol: &str) -> Self {
        let h = if protocol.len() <= 32 {
            let mut h = [0; 32];
            h[..protocol.len()].copy_from_slice(protocol.as_bytes());
            h
        } else {
            use sha2::Digest;
            Sha256::digest(protocol).into()
        };
        Self { ck: h, h }
    }
}

pub struct HandshakeState<St: States + ?Sized> {
    pub cipher: CipherState<St::EncryptionKey>,
    pub symm: SymmetricState,

    /// local static key pair
    s: <St::StaticKey as Val>::Val<KeyPair>,
    /// local ephemeral key pair
    e: <St::EphemeralKey as Val>::Val<EphKeyPair>,
    /// remote static public key
    rs: <St::RemoteStaticKey as Val>::Val<PubKey>,
    /// remote ephemeral public key
    re: <St::RemoteEphemeralKey as Val>::Val<PubKey>,
}

impl<St: States + ?Sized> HandshakeState<St> {
    pub fn with_prologue(mut self, b: &[u8]) -> Self {
        self.symm = self.symm.mix_hash(b);
        self
    }
}

impl<St: States<EncryptionKey = Known> + ?Sized> HandshakeState<St> {
    pub fn encrypt_payload(&mut self, plaintext: &[u8], b: &mut BytesMut) {
        self.symm.encrypt_and_hash(plaintext, b, &mut self.cipher);
    }
    pub fn decrypt_payload(
        &mut self,
        ciphertext: BytesMut,
    ) -> Result<BytesMut, chacha20poly1305::Error> {
        self.symm.decrypt_and_hash(ciphertext, &mut self.cipher)
    }
}

impl
    HandshakeState<
        dyn States<
            StaticKey = Unknown,
            EphemeralKey = Unknown,
            RemoteStaticKey = Unknown,
            RemoteEphemeralKey = Unknown,
            EncryptionKey = Unknown,
            Side = Initiator,
        >,
    >
{
    pub fn initiator(pattern: &str) -> Self {
        Self {
            cipher: CipherState::default(),
            symm: SymmetricState::new(pattern),
            s: Unknown,
            e: Unknown,
            rs: Unknown,
            re: Unknown,
        }
    }
}

impl
    HandshakeState<
        dyn States<
            StaticKey = Unknown,
            EphemeralKey = Unknown,
            RemoteStaticKey = Unknown,
            RemoteEphemeralKey = Unknown,
            EncryptionKey = Unknown,
            Side = Responder,
        >,
    >
{
    pub fn responder(pattern: &str) -> Self {
        Self {
            cipher: CipherState::default(),
            symm: SymmetricState::new(pattern),
            s: Unknown,
            e: Unknown,
            rs: Unknown,
            re: Unknown,
        }
    }
}

impl<St: States<StaticKey = Unknown> + ?Sized> HandshakeState<St> {
    pub fn with_static_key(
        self,
        key: StaticSecret,
    ) -> HandshakeState<<St as StatesExt>::WithStaticKey> {
        HandshakeState {
            cipher: self.cipher,
            symm: self.symm,
            s: KeyPair(key),
            e: self.e,
            rs: self.rs,
            re: self.re,
        }
    }
}

#[cfg(unsafe_typestate_noise_vectors)]
impl<St: States<EphemeralKey = Unknown> + ?Sized> HandshakeState<St> {
    pub fn with_ephemeral_key(
        self,
        key: StaticSecret,
    ) -> HandshakeState<<St as StatesExt>::WithEphemeralKey> {
        HandshakeState {
            cipher: self.cipher,
            symm: self.symm,
            s: self.s,
            e: EphKeyPair(key),
            rs: self.rs,
            re: self.re,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn check_ik() {
        type IkPre0 = hlist![S];
        type IkMsg0 = hlist![E, Es, S, Ss, Payload];
        type IkMsg1 = hlist![E, Ee, Se, Payload];

        let hs_init = HandshakeState::initiator("Noise_IK_25519_ChaChaPoly_SHA256")
            .with_static_key(StaticSecret::random());
        let hs_resp = HandshakeState::responder("Noise_IK_25519_ChaChaPoly_SHA256")
            .with_static_key(StaticSecret::random());

        let mut msg = BytesMut::new();
        let hs_resp = IkPre0::send_premsg(&mut msg, hs_resp);
        let hs_init = IkPre0::recv_premsg(&mut msg, hs_init).unwrap();

        let mut msg = BytesMut::new();
        let hs_init = IkMsg0::send_with_payload(&mut msg, hs_init, b"hello");
        let (hs_resp, data) = IkMsg0::recv_with_payload(&mut msg, hs_resp).unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));

        let mut msg = BytesMut::new();
        let hs_resp = IkMsg1::send_with_payload(&mut msg, hs_resp, b"goodbye");
        let (hs_init, data) = IkMsg1::recv_with_payload(&mut msg, hs_init).unwrap();
        assert_eq!(data, Bytes::from_static(b"goodbye"));

        assert_eq!(hs_init.cipher.k.0, hs_resp.cipher.k.0);
        assert_eq!(hs_init.symm.ck, hs_resp.symm.ck);
        assert_eq!(hs_init.symm.h, hs_resp.symm.h);
    }

    #[test]
    fn check_kx() {
        type KxPre0 = hlist![S];
        type KxMsg0 = hlist![E, Payload];
        type KxMsg1 = hlist![E, Ee, Se, S, Es, Payload];

        let hs_init = HandshakeState::initiator("Noise_KX_25519_ChaChaPoly_SHA256")
            .with_static_key(StaticSecret::random());
        let hs_resp = HandshakeState::responder("Noise_KX_25519_ChaChaPoly_SHA256")
            .with_static_key(StaticSecret::random());

        let mut msg = BytesMut::new();
        let hs_init = KxPre0::send_premsg(&mut msg, hs_init);
        let hs_resp = KxPre0::recv_premsg(&mut msg, hs_resp).unwrap();

        let mut msg = BytesMut::new();
        let hs_init = KxMsg0::send_with_payload(&mut msg, hs_init, b"hello");
        let (hs_resp, data) = KxMsg0::recv_with_payload(&mut msg, hs_resp).unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));

        let mut msg = BytesMut::new();
        let hs_resp = KxMsg1::send_with_payload(&mut msg, hs_resp, b"goodbye");
        let (hs_init, data) = KxMsg1::recv_with_payload(&mut msg, hs_init).unwrap();
        assert_eq!(data, Bytes::from_static(b"goodbye"));

        assert_eq!(hs_init.cipher.k.0, hs_resp.cipher.k.0);
        assert_eq!(hs_init.symm.ck, hs_resp.symm.ck);
        assert_eq!(hs_init.symm.h, hs_resp.symm.h);
    }
}
