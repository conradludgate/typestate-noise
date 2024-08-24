use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

/// Appends "EncryptAndHash(s.public_key)" to the buffer.
pub struct S<T> {
    t: T,
}

impl S<()> {
    pub fn recv<K0, K1, K3, K4>(
        b: &mut BytesMut,
        mut state: HandshakeState<K0, K1, Unknown, K3, K4>,
    ) -> Result<HandshakeState<K0, K1, Known, K3, K4>, chacha20poly1305::Error>
    where
        KeyPair: Val<K0>,
        EphKeyPair: Val<K1>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
        // typecheck that rs is unknown
        let _: () = state.rs;

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

    pub fn send<K1, K2, K3, K4>(
        b: &mut Vec<u8>,
        mut state: HandshakeState<Known, K1, K2, K3, K4>,
    ) -> HandshakeState<Known, K1, K2, K3, K4>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K2> + Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
        let pk = PublicKey::from(&state.s.0);
        state
            .symm
            .encrypt_and_hash(pk.as_bytes(), b, &mut state.cipher);
        state
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct E<T> {
    t: T,
}

impl E<()> {
    pub fn recv<K0, K1, K2, K4>(
        b: &mut BytesMut,
        mut state: HandshakeState<K0, K1, K2, Unknown, K4>,
    ) -> Result<HandshakeState<K0, K1, K2, Known, K4>, chacha20poly1305::Error>
    where
        KeyPair: Val<K0>,
        EphKeyPair: Val<K1>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
        // typecheck that re is unknown
        let _: () = state.re;

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

    pub fn send<K0, K2, K3, K4>(
        b: &mut Vec<u8>,
        mut state: HandshakeState<K0, Unknown, K2, K3, K4>,
    ) -> HandshakeState<K0, Known, K2, K3, K4>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K2> + Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
        let ek = ReusableSecret::random();
        let pk = PublicKey::from(&ek);
        b.extend_from_slice(pk.as_bytes());
        state.symm = state.symm.mix_hash(pk.as_bytes());

        HandshakeState::<K0, Known, K2, K3, K4> {
            cipher: state.cipher,
            symm: state.symm,
            s: state.s,
            e: EphKeyPair(ek),
            rs: state.rs,
            re: state.re,
        }
    }
}

/// Generates a new ephemeral keypair, appends the public key to the buffer and calls mixhash
pub struct Ee<T> {
    t: T,
}

impl Ee<()> {
    pub fn recv<K0, K2, K4>(
        b: &mut BytesMut,
        state: HandshakeState<K0, Known, K2, Known, K4>,
    ) -> Result<HandshakeState<K0, Known, K2, Known, Known>, chacha20poly1305::Error>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn send<K0, K2, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, K2, Known, K4>,
    ) -> HandshakeState<K0, Known, K2, Known, Known>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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
pub struct Ss<T> {
    t: T,
}

impl Ss<()> {
    pub fn recv<K1, K3, K4>(
        b: &mut BytesMut,
        state: HandshakeState<Known, K1, Known, K3, K4>,
    ) -> Result<HandshakeState<Known, K1, Known, K3, Known>, chacha20poly1305::Error>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn send<K1, K3, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, Known, K3, K4>,
    ) -> HandshakeState<Known, K1, Known, K3, Known>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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
pub struct Es<T> {
    t: T,
}

impl Es<()> {
    pub fn recv_init<K0, K3, K4>(
        b: &mut BytesMut,
        state: HandshakeState<K0, Known, Known, K3, K4>,
    ) -> Result<HandshakeState<K0, Known, Known, K3, Known>, chacha20poly1305::Error>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn init<K0, K3, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, Known, K3, K4>,
    ) -> HandshakeState<K0, Known, Known, K3, Known>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

impl Es<()> {
    pub fn recv_resp<K1, K2, K4>(
        b: &mut BytesMut,
        state: HandshakeState<Known, K1, K2, Known, K4>,
    ) -> Result<HandshakeState<Known, K1, K2, Known, Known>, chacha20poly1305::Error>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn resp<K1, K2, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, K2, Known, K4>,
    ) -> HandshakeState<Known, K1, K2, Known, Known>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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
pub struct Se<T> {
    t: T,
}

impl Se<()> {
    pub fn recv_resp<K0, K3, K4>(
        b: &mut BytesMut,
        state: HandshakeState<K0, Known, Known, K3, K4>,
    ) -> Result<HandshakeState<K0, Known, Known, K3, Known>, chacha20poly1305::Error>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn resp<K0, K3, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<K0, Known, Known, K3, K4>,
    ) -> HandshakeState<K0, Known, Known, K3, Known>
    where
        KeyPair: Val<K0>,
        PubKey: Val<K3>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

impl Es<()> {
    pub fn recv_send<K1, K2, K4>(
        b: &mut BytesMut,
        state: HandshakeState<Known, K1, K2, Known, K4>,
    ) -> Result<HandshakeState<Known, K1, K2, Known, Known>, chacha20poly1305::Error>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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

    pub fn send<K1, K2, K4>(
        b: &mut Vec<u8>,
        state: HandshakeState<Known, K1, K2, Known, K4>,
    ) -> HandshakeState<Known, K1, K2, Known, Known>
    where
        EphKeyPair: Val<K1>,
        PubKey: Val<K2>,
        Key: Val<K4>,
        CipherState<K4>: CipherStateAlg,
    {
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
pub struct Known;
pub struct Unknown;

pub struct EphKeyPair(ReusableSecret);
pub struct KeyPair(StaticSecret);
pub struct PubKey(PublicKey);
pub struct Key(chacha20poly1305::Key);

pub trait Val<K> {
    type T;
}

impl Val<Known> for EphKeyPair {
    type T = EphKeyPair;
}

impl Val<Unknown> for EphKeyPair {
    type T = ();
}

impl Val<Known> for KeyPair {
    type T = KeyPair;
}

impl Val<Unknown> for KeyPair {
    type T = ();
}

impl Val<Known> for PubKey {
    type T = PubKey;
}

impl Val<Unknown> for PubKey {
    type T = ();
}

impl Val<Known> for Key {
    type T = Key;
}

impl Val<Unknown> for Key {
    type T = ();
}

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
        Key: Val<K>,
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
        Key: Val<K>,
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
    Key: Val<K>,
{
    /// cipher key
    k: <Key as Val<K>>::T,
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
    KeyPair: Val<K0>,
    EphKeyPair: Val<K1>,
    PubKey: Val<K2> + Val<K3>,
    Key: Val<K4>,
{
    cipher: CipherState<K4>,
    symm: SymmetricState,

    /// local static key pair
    s: <KeyPair as Val<K0>>::T,
    /// local ephemeral key pair
    e: <EphKeyPair as Val<K1>>::T,
    /// remote static public key
    rs: <PubKey as Val<K2>>::T,
    /// remote ephemeral public key
    re: <PubKey as Val<K3>>::T,
}
