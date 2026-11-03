use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};

use serde::Deserialize;
use typestate_noise::{
    crypto::{ChaChaPoly, Dh, Hash, Sha256, Sha512, Suite, X25519},
    handshake::{
        states::*, Complete, DhRequest, DhResult, Error, Handshake, NoPsk, Psk, Psk0, Psk0And2,
        Psk2, PskMode, StaticDhStep, Transport, Written, IK, XX,
    },
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

thread_local! {
    static EPHEMERALS: RefCell<VecDeque<[u8; 32]>> = const { RefCell::new(VecDeque::new()) };
    static ERASED: Cell<usize> = const { Cell::new(0) };
}

// Deterministic credentials are confined to the test backend. Production X25519
// never exposes a reusable ephemeral credential setter.
struct TestSecret(StaticSecret);

impl Zeroize for TestSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
        ERASED.set(ERASED.get() + 1);
    }
}

struct FixtureDh;

impl Dh for FixtureDh {
    const NAME: &'static str = "25519";
    const PUBLIC_KEY_LEN: usize = 32;
    type PublicKey = [u8; 32];
    type EphemeralSecret = TestSecret;
    type SharedSecret = [u8; 32];

    fn generate() -> Result<Self::EphemeralSecret, Error> {
        EPHEMERALS
            .with(|keys| keys.borrow_mut().pop_front())
            .map(|key| TestSecret(StaticSecret::from(key)))
            .ok_or(Error::Crypto)
    }

    fn public(secret: &Self::EphemeralSecret) -> Self::PublicKey {
        PublicKey::from(&secret.0).to_bytes()
    }

    fn parse_public(bytes: &[u8]) -> Result<Self::PublicKey, Error> {
        X25519::parse_public(bytes)
    }

    fn dh(
        secret: &Self::EphemeralSecret,
        peer: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Error> {
        Ok(secret.0.diffie_hellman(&(*peer).into()).to_bytes())
    }
}

type C<H = Sha256> = Suite<FixtureDh, ChaChaPoly, H>;

fn external<H: Hash, S: StaticDhStep, M: PskMode>(
    request: &DhRequest<'_, C<H>, S, M>,
    secret: &StaticSecret,
) -> DhResult<C<H>> {
    assert_eq!(
        *request.local_public_key(),
        PublicKey::from(secret).to_bytes()
    );
    DhResult::new(
        secret
            .diffie_hellman(&(*request.peer_public_key()).into())
            .to_bytes(),
    )
}

#[derive(Deserialize)]
struct Vector {
    protocol_name: String,
    init_prologue: String,
    resp_prologue: String,
    init_static: String,
    resp_static: String,
    init_ephemeral: String,
    resp_ephemeral: String,
    #[serde(default)]
    init_psks: Vec<String>,
    #[serde(default)]
    resp_psks: Vec<String>,
    messages: Vec<VectorMessage>,
}

#[derive(Deserialize)]
struct VectorMessage {
    payload: String,
    ciphertext: String,
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}
fn key(value: &str) -> [u8; 32] {
    bytes(value).try_into().unwrap()
}
fn public(value: &str) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(key(value))).to_bytes()
}

fn fixture(pattern: &str, hash: &str) -> Vector {
    let data: serde_json::Value = serde_json::from_str(include_str!("snow.json")).unwrap();
    let name = format!("Noise_{pattern}_25519_ChaChaPoly_{hash}");
    let value = data["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["protocol_name"] == name)
        .unwrap()
        .clone();
    serde_json::from_value(value).unwrap()
}

fn seed(vector: &Vector) {
    EPHEMERALS.with(|keys| {
        *keys.borrow_mut() = [key(&vector.init_ephemeral), key(&vector.resp_ephemeral)].into()
    });
}

fn check_message(wire: &[u8], expected: &VectorMessage) {
    assert_eq!(wire, bytes(&expected.ciphertext));
}

// Adapt the distinct public PSK token transitions into common test drivers.
trait TestMode: PskMode + Sized {
    fn xx_initiator<H: Hash>(v: &Vector) -> Handshake<C<H>, XxInitiatorWrite1, Self>;
    fn xx_responder<H: Hash>(v: &Vector) -> Handshake<C<H>, XxResponderRead1, Self>;
    fn ik_initiator<H: Hash>(v: &Vector) -> Handshake<C<H>, IkInitiatorWrite1, Self>;
    fn ik_responder<H: Hash>(v: &Vector) -> Handshake<C<H>, IkResponderRead1, Self>;
    fn xx_send2<'a, H: Hash>(
        request: DhRequest<'a, C<H>, XxResponderDh2, Self>,
        shared: DhResult<C<H>>,
        psks: &[String],
    ) -> Written<'a, C<H>, XxResponderRead3, Self>;
    fn xx_read2<'a, H: Hash>(
        state: Handshake<C<H>, XxInitiatorRead2, Self>,
        input: &'a mut [u8],
        psks: &[String],
    ) -> Written<'a, C<H>, XxInitiatorWrite3, Self>;
    fn ik_send2<'a, H: Hash>(
        state: Handshake<C<H>, IkResponderWrite2, Self>,
        payload: &[u8],
        output: &'a mut [u8],
        psks: &[String],
        in_place: bool,
    ) -> Complete<'a, C<H>>;
    fn ik_read2<'a, H: Hash>(
        request: DhRequest<'a, C<H>, IkInitiatorDh2, Self>,
        shared: DhResult<C<H>>,
        psks: &[String],
    ) -> Complete<'a, C<H>>;
}

macro_rules! finish2 {
    (direct, $operation:expr, $psks:ident) => {
        $operation.unwrap()
    };
    (psk, $operation:expr, $psks:ident) => {
        $operation
            .unwrap()
            .provide_psk(Psk::new(key($psks.last().unwrap())))
            .unwrap()
    };
}

macro_rules! test_mode {
    ($mode:ty, $i:ident, $r:ident, [$($zero:expr)?], $finish:ident) => {
        impl TestMode for $mode {
            fn xx_initiator<H: Hash>(v: &Vector) -> Handshake<C<H>, XxInitiatorWrite1, Self> {
                XX::$i::<C<H>>(&bytes(&v.init_prologue) $(, Psk::new(key(&v.init_psks[$zero])))?).unwrap()
            }
            fn xx_responder<H: Hash>(v: &Vector) -> Handshake<C<H>, XxResponderRead1, Self> {
                XX::$r::<C<H>>(&bytes(&v.resp_prologue) $(, Psk::new(key(&v.resp_psks[$zero])))?).unwrap()
            }
            fn ik_initiator<H: Hash>(v: &Vector) -> Handshake<C<H>, IkInitiatorWrite1, Self> {
                IK::$i::<C<H>>(&bytes(&v.init_prologue), public(&v.init_static), public(&v.resp_static) $(, Psk::new(key(&v.init_psks[$zero])))?).unwrap()
            }
            fn ik_responder<H: Hash>(v: &Vector) -> Handshake<C<H>, IkResponderRead1, Self> {
                IK::$r::<C<H>>(&bytes(&v.resp_prologue), public(&v.resp_static) $(, Psk::new(key(&v.resp_psks[$zero])))?).unwrap()
            }
            fn xx_send2<'a, H: Hash>(request: DhRequest<'a, C<H>, XxResponderDh2, Self>, shared: DhResult<C<H>>, _psks: &[String]) -> Written<'a, C<H>, XxResponderRead3, Self> {
                finish2!($finish, request.resume(shared), _psks)
            }
            fn xx_read2<'a, H: Hash>(state: Handshake<C<H>, XxInitiatorRead2, Self>, input: &'a mut [u8], _psks: &[String]) -> Written<'a, C<H>, XxInitiatorWrite3, Self> {
                let result = state.read_message(input);
                finish2!($finish, result, _psks)
            }
            fn ik_send2<'a, H: Hash>(state: Handshake<C<H>, IkResponderWrite2, Self>, payload: &[u8], output: &'a mut [u8], _psks: &[String], in_place: bool) -> Complete<'a, C<H>> {
                let result = if in_place {
                    let offset = Handshake::<C<H>, IkResponderWrite2, Self>::PAYLOAD_OFFSET;
                    output[offset..offset + payload.len()].copy_from_slice(payload);
                    state.write_message_in_place(output, payload.len())
                } else { state.write_message(payload, output) };
                finish2!($finish, result, _psks)
            }
            fn ik_read2<'a, H: Hash>(request: DhRequest<'a, C<H>, IkInitiatorDh2, Self>, shared: DhResult<C<H>>, _psks: &[String]) -> Complete<'a, C<H>> {
                finish2!($finish, request.resume(shared), _psks)
            }
        }
    };
}

test_mode!(NoPsk, initiator, responder, [], direct);
test_mode!(Psk0, initiator_psk0, responder_psk0, [0], direct);
test_mode!(Psk2, initiator_psk2, responder_psk2, [], psk);
test_mode!(Psk0And2, initiator_psk0_psk2, responder_psk0_psk2, [0], psk);

fn run_xx<H: Hash, M: TestMode>(v: &Vector, in_place: bool) -> (Transport<C<H>>, Transport<C<H>>) {
    seed(v);
    let si = StaticSecret::from(key(&v.init_static));
    let sr = StaticSecret::from(key(&v.resp_static));
    let i = M::xx_initiator::<H>(v);
    let r = M::xx_responder::<H>(v);

    let payload = bytes(&v.messages[0].payload);
    let mut wire = vec![0; Handshake::<C<H>, XxInitiatorWrite1, M>::OVERHEAD + payload.len()];
    let start = wire.as_ptr();
    let (i, sent) = if in_place {
        let offset = Handshake::<C<H>, XxInitiatorWrite1, M>::PAYLOAD_OFFSET;
        wire[offset..offset + payload.len()].copy_from_slice(&payload);
        i.write_message_in_place(&mut wire, payload.len()).unwrap()
    } else {
        i.write_message(&payload, &mut wire).unwrap()
    };
    assert_eq!(start, sent.as_ptr());
    check_message(sent, &v.messages[0]);
    let (r, received) = r.read_message(sent).unwrap();
    assert_eq!(received, payload);

    let payload = bytes(&v.messages[1].payload);
    let mut wire = vec![0; Handshake::<C<H>, XxResponderWrite2, M>::OVERHEAD + payload.len()];
    let request = if in_place {
        let offset = Handshake::<C<H>, XxResponderWrite2, M>::PAYLOAD_OFFSET;
        wire[offset..offset + payload.len()].copy_from_slice(&payload);
        r.write_message_in_place(PublicKey::from(&sr).to_bytes(), &mut wire, payload.len())
            .unwrap()
    } else {
        r.write_message(PublicKey::from(&sr).to_bytes(), &payload, &mut wire)
            .unwrap()
    };
    let shared = external(&request, &sr);
    let (r, sent) = M::xx_send2(request, shared, &v.resp_psks);
    check_message(sent, &v.messages[1]);
    let (i, received) = M::xx_read2(i, sent, &v.init_psks);
    assert_eq!(received, payload);

    let payload = bytes(&v.messages[2].payload);
    let mut wire = vec![0; Handshake::<C<H>, XxInitiatorWrite3, M>::OVERHEAD + payload.len()];
    let request = if in_place {
        let offset = Handshake::<C<H>, XxInitiatorWrite3, M>::PAYLOAD_OFFSET;
        wire[offset..offset + payload.len()].copy_from_slice(&payload);
        i.write_message_in_place(PublicKey::from(&si).to_bytes(), &mut wire, payload.len())
            .unwrap()
    } else {
        i.write_message(PublicKey::from(&si).to_bytes(), &payload, &mut wire)
            .unwrap()
    };
    let shared = external(&request, &si);
    let (i, sent) = request.resume(shared).unwrap();
    check_message(sent, &v.messages[2]);
    let (r, received) = r.read_message(sent).unwrap();
    assert_eq!(received, payload);
    (i, r)
}

fn run_ik<H: Hash, M: TestMode>(v: &Vector, in_place: bool) -> (Transport<C<H>>, Transport<C<H>>) {
    seed(v);
    let si = StaticSecret::from(key(&v.init_static));
    let sr = StaticSecret::from(key(&v.resp_static));
    let i = M::ik_initiator::<H>(v);
    let r = M::ik_responder::<H>(v);

    let payload = bytes(&v.messages[0].payload);
    let mut wire = vec![0; Handshake::<C<H>, IkInitiatorWrite1, M>::OVERHEAD + payload.len()];
    let request = if in_place {
        let offset = Handshake::<C<H>, IkInitiatorWrite1, M>::PAYLOAD_OFFSET;
        wire[offset..offset + payload.len()].copy_from_slice(&payload);
        i.write_message_in_place(&mut wire, payload.len()).unwrap()
    } else {
        i.write_message(&payload, &mut wire).unwrap()
    };
    let shared = external(&request, &si);
    let (i, sent) = request.resume(shared).unwrap();
    check_message(sent, &v.messages[0]);
    let request = r.read_message(sent).unwrap();
    let shared = external(&request, &sr);
    let request = request.resume(shared).unwrap();
    let shared = external(&request, &sr);
    let (r, received) = request.resume(shared).unwrap();
    assert_eq!(received, payload);

    let payload = bytes(&v.messages[1].payload);
    let mut wire = vec![0; payload.len() + 48];
    let (r, sent) = M::ik_send2(r, &payload, &mut wire, &v.resp_psks, in_place);
    check_message(sent, &v.messages[1]);
    let request = i.read_message(sent).unwrap();
    let shared = external(&request, &si);
    let (i, received) = M::ik_read2(request, shared, &v.init_psks);
    assert_eq!(received, payload);
    (i, r)
}

fn snow_pair(v: &Vector) -> (snow::HandshakeState, snow::HandshakeState) {
    let si = key(&v.init_static);
    let sr = key(&v.resp_static);
    let ei = key(&v.init_ephemeral);
    let er = key(&v.resp_ephemeral);
    let rs = public(&v.resp_static);
    let pi = bytes(&v.init_prologue);
    let pr = bytes(&v.resp_prologue);
    let mut builder = snow::Builder::new(v.protocol_name.parse().unwrap())
        .local_private_key(&si)
        .fixed_ephemeral_key_for_testing_only(&ei)
        .prologue(&pi);
    if v.protocol_name.starts_with("Noise_IK") {
        builder = builder.remote_public_key(&rs);
    }
    let init_psks: Vec<_> = v.init_psks.iter().map(|s| key(s)).collect();
    let resp_psks: Vec<_> = v.resp_psks.iter().map(|s| key(s)).collect();
    let positions: Vec<u8> = [0, 2]
        .into_iter()
        .filter(|position| v.protocol_name.contains(&format!("psk{position}")))
        .collect();
    for (position, psk) in positions.iter().zip(&init_psks) {
        builder = builder.psk(*position, psk);
    }
    let snow_i = builder.build_initiator().unwrap();
    let mut builder = snow::Builder::new(v.protocol_name.parse().unwrap())
        .local_private_key(&sr)
        .fixed_ephemeral_key_for_testing_only(&er)
        .prologue(&pr);
    for (position, psk) in positions.iter().zip(&resp_psks) {
        builder = builder.psk(*position, psk);
    }
    (snow_i, builder.build_responder().unwrap())
}

fn psk_fixture(pattern: &str, modifier: &str, hash: &str) -> Vector {
    if modifier == "psk0+psk2" {
        // Exercise the repository's independent, fixed combined-PSK vectors.
        return fixture(&format!("{pattern}{modifier}"), hash);
    }
    // The bundled data has no individual psk0/psk2 cases. Produce their expected
    // ciphertext with Snow, retaining the bundled credentials and payloads.
    let mut v = fixture(pattern, hash);
    v.protocol_name = format!("Noise_{pattern}{modifier}_25519_ChaChaPoly_{hash}");
    v.init_psks = vec![hex::encode([42; 32])];
    v.resp_psks = v.init_psks.clone();
    let (mut i, mut r) = snow_pair(&v);
    let mut wire = [0; 65535];
    let mut output = [0; 65535];
    for (index, message) in v.messages.iter_mut().enumerate() {
        let (sender, receiver) = if index % 2 == 0 {
            (&mut i, &mut r)
        } else {
            (&mut r, &mut i)
        };
        let length = sender
            .write_message(&bytes(&message.payload), &mut wire)
            .unwrap();
        message.ciphertext = hex::encode(&wire[..length]);
        receiver.read_message(&wire[..length], &mut output).unwrap();
    }
    v
}

fn interoperate<H: Hash>(v: &Vector, mut i: Transport<C<H>>, mut r: Transport<C<H>>) {
    let (mut snow_i, mut snow_r) = snow_pair(v);
    let mut buffer = [0; 65535];
    let mut output = [0; 65535];
    for (index, message) in v.messages.iter().enumerate() {
        let (sender, receiver) = if index % 2 == 0 {
            (&mut snow_i, &mut snow_r)
        } else {
            (&mut snow_r, &mut snow_i)
        };
        let length = sender
            .write_message(&bytes(&message.payload), &mut buffer)
            .unwrap();
        check_message(&buffer[..length], message);
        receiver
            .read_message(&buffer[..length], &mut output)
            .unwrap();
    }
    assert_eq!(i.handshake_hash().as_ref(), snow_i.get_handshake_hash());
    assert_eq!(r.handshake_hash().as_ref(), snow_r.get_handshake_hash());
    assert_eq!(*i.remote_static(), public(&v.resp_static));
    assert_eq!(*r.remote_static(), public(&v.init_static));
    let mut snow_i = snow_i.into_transport_mode().unwrap();
    let mut snow_r = snow_r.into_transport_mode().unwrap();

    // Check both implementations as sender and receiver, with several nonces.
    for payload in [b"transport".as_slice(), b"", b"another message"] {
        let mut wire = vec![0; payload.len() + 16];
        wire[..payload.len()].copy_from_slice(payload);
        let encrypted = i.encrypt(&mut wire).unwrap();
        let length = snow_r.read_message(encrypted, &mut output).unwrap();
        assert_eq!(&output[..length], payload);
        let length = snow_i.write_message(payload, &mut buffer).unwrap();
        assert_eq!(r.decrypt(&mut buffer[..length]).unwrap(), payload);

        wire[..payload.len()].copy_from_slice(payload);
        let encrypted = r.encrypt(&mut wire).unwrap();
        let length = snow_i.read_message(encrypted, &mut output).unwrap();
        assert_eq!(&output[..length], payload);
        let length = snow_r.write_message(payload, &mut buffer).unwrap();
        assert_eq!(i.decrypt(&mut buffer[..length]).unwrap(), payload);
    }

    // Authentication failure must not advance the receive nonce.
    let length = snow_r.write_message(b"authenticated", &mut buffer).unwrap();
    let original = buffer[..length].to_vec();
    buffer[length - 1] ^= 1;
    assert_eq!(i.decrypt(&mut buffer[..length]), Err(Error::Crypto));
    assert_eq!(i.decrypt(&mut original.clone()).unwrap(), b"authenticated");
    assert_eq!(i.decrypt(&mut original.clone()), Err(Error::Crypto)); // replay
}

#[test]
fn xx_vectors_and_snow_transport() {
    for in_place in [false, true] {
        let v = fixture("XX", "SHA256");
        let (i, r) = run_xx::<Sha256, NoPsk>(&v, in_place);
        interoperate(&v, i, r);
        let v = fixture("XX", "SHA512");
        let (i, r) = run_xx::<Sha512, NoPsk>(&v, in_place);
        interoperate(&v, i, r);
    }
}

#[test]
fn ik_vectors_and_snow_transport() {
    for in_place in [false, true] {
        let v = fixture("IK", "SHA256");
        let (i, r) = run_ik::<Sha256, NoPsk>(&v, in_place);
        interoperate(&v, i, r);
        let v = fixture("IK", "SHA512");
        let (i, r) = run_ik::<Sha512, NoPsk>(&v, in_place);
        interoperate(&v, i, r);
    }
}

macro_rules! psk_test {
    ($name:ident, $pattern:literal, $modifier:literal, $mode:ty, $run:ident) => {
        #[test]
        fn $name() {
            for in_place in [false, true] {
                let v = psk_fixture($pattern, $modifier, "SHA256");
                let (i, r) = $run::<Sha256, $mode>(&v, in_place);
                interoperate(&v, i, r);
                let v = psk_fixture($pattern, $modifier, "SHA512");
                let (i, r) = $run::<Sha512, $mode>(&v, in_place);
                interoperate(&v, i, r);
            }
        }
    };
}

psk_test!(xx_psk0, "XX", "psk0", Psk0, run_xx);
psk_test!(xx_psk2, "XX", "psk2", Psk2, run_xx);
psk_test!(xx_psk0_psk2, "XX", "psk0+psk2", Psk0And2, run_xx);
psk_test!(ik_psk0, "IK", "psk0", Psk0, run_ik);
psk_test!(ik_psk2, "IK", "psk2", Psk2, run_ik);
psk_test!(ik_psk0_psk2, "IK", "psk0+psk2", Psk0And2, run_ik);

#[test]
fn wrong_psk0_fails_in_the_first_message() {
    let v = psk_fixture("XX", "psk0", "SHA256");
    seed(&v);
    let i = <Psk0 as TestMode>::xx_initiator::<Sha256>(&v);
    let r = XX::responder_psk0::<C>(&bytes(&v.resp_prologue), Psk::new([99; 32])).unwrap();
    let mut wire = [0; 128];
    let (_, sent) = i.write_message(b"secret", &mut wire).unwrap();
    assert!(matches!(r.read_message(sent), Err(Error::Crypto)));

    let v = psk_fixture("IK", "psk0", "SHA256");
    seed(&v);
    let si = StaticSecret::from(key(&v.init_static));
    let sr = StaticSecret::from(key(&v.resp_static));
    let i = <Psk0 as TestMode>::ik_initiator::<Sha256>(&v);
    let r = IK::responder_psk0::<C>(
        &bytes(&v.resp_prologue),
        public(&v.resp_static),
        Psk::new([99; 32]),
    )
    .unwrap();
    let request = i.write_message(b"secret", &mut wire).unwrap();
    let shared = external(&request, &si);
    let (_, sent) = request.resume(shared).unwrap();
    let request = r.read_message(sent).unwrap();
    let shared = external(&request, &sr);
    assert!(matches!(request.resume(shared), Err(Error::Crypto)));
}

#[test]
fn wrong_psk2_fails_before_payload_is_returned() {
    let v = psk_fixture("XX", "psk2", "SHA256");
    seed(&v);
    let i = <Psk2 as TestMode>::xx_initiator::<Sha256>(&v);
    let (i, _) = i
        .write_message(&bytes(&v.messages[0].payload), &mut [0; 128])
        .unwrap();
    let mut wire = bytes(&v.messages[1].ciphertext);
    let request = i.read_message(&mut wire).unwrap();
    assert_eq!(*request.remote_static(), public(&v.resp_static));
    assert!(matches!(
        request.provide_psk(Psk::new([99; 32])),
        Err(Error::Crypto)
    ));

    let v = psk_fixture("IK", "psk2", "SHA256");
    seed(&v);
    let si = StaticSecret::from(key(&v.init_static));
    let i = <Psk2 as TestMode>::ik_initiator::<Sha256>(&v);
    let mut first = [0; 128];
    let request = i
        .write_message(&bytes(&v.messages[0].payload), &mut first)
        .unwrap();
    let shared = external(&request, &si);
    let (i, _) = request.resume(shared).unwrap();
    let mut wire = bytes(&v.messages[1].ciphertext);
    let request = i.read_message(&mut wire).unwrap();
    let shared = external(&request, &si);
    let request = request.resume(shared).unwrap();
    assert!(matches!(
        request.provide_psk(Psk::new([99; 32])),
        Err(Error::Crypto)
    ));
}

#[test]
fn psk_modes_validate_first_message_overhead() {
    assert_eq!(Handshake::<C, XxInitiatorWrite1, Psk2>::PAYLOAD_OFFSET, 32);
    assert_eq!(Handshake::<C, XxInitiatorWrite1, Psk2>::OVERHEAD, 48);
    assert_eq!(Handshake::<C, XxInitiatorWrite1, Psk0>::OVERHEAD, 48);
    for length in 0..48 {
        let r = XX::responder_psk2::<C>(b"").unwrap();
        assert!(matches!(
            r.read_message(&mut vec![0; length]),
            Err(Error::InvalidMessage)
        ));
    }
    assert!(matches!(
        XX::initiator_psk2::<C>(b"")
            .unwrap()
            .write_message(b"", &mut [0; 47]),
        Err(Error::BufferTooSmall)
    ));
}

#[test]
fn cancelled_async_psk_request_erases_ephemeral() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let v = psk_fixture("XX", "psk2", "SHA256");
    seed(&v);
    let i = <Psk2 as TestMode>::xx_initiator::<Sha256>(&v);
    let (i, _) = i
        .write_message(&bytes(&v.messages[0].payload), &mut [0; 128])
        .unwrap();
    let mut wire = bytes(&v.messages[1].ciphertext);
    let request = i.read_message(&mut wire).unwrap();
    let before = ERASED.get();
    let future = async move {
        let psk = std::future::pending::<Psk>().await;
        request.provide_psk(psk)
    };
    let mut future = Box::pin(future);
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    assert_eq!(ERASED.get(), before + 1);
    wire.fill(0);
}

#[test]
fn malformed_first_messages_and_output_bounds() {
    for length in 0..32 {
        assert!(matches!(
            XX::responder::<C>(b"")
                .unwrap()
                .read_message(&mut vec![0; length]),
            Err(Error::InvalidMessage)
        ));
    }
    for length in 0..96 {
        assert!(matches!(
            IK::responder::<C>(b"", [1; 32])
                .unwrap()
                .read_message(&mut vec![0; length]),
            Err(Error::InvalidMessage)
        ));
    }
    assert!(matches!(
        XX::responder::<C>(b"")
            .unwrap()
            .read_message(&mut vec![0; 65536]),
        Err(Error::InvalidMessage)
    ));
    assert!(matches!(
        XX::initiator::<C>(b"")
            .unwrap()
            .write_message(b"", &mut [0; 31]),
        Err(Error::BufferTooSmall)
    ));
    assert!(matches!(
        XX::initiator::<C>(b"")
            .unwrap()
            .write_message_in_place(&mut [], usize::MAX),
        Err(Error::MessageTooLong)
    ));
}

#[test]
fn cancelled_async_static_dh_erases_ephemeral() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    EPHEMERALS.with(|keys| *keys.borrow_mut() = [[7; 32], [8; 32]].into());
    let r = XX::responder::<C>(b"").unwrap();
    let mut first = [0; 32];
    let (_, first) = XX::initiator::<C>(b"")
        .unwrap()
        .write_message(b"", &mut first)
        .unwrap();
    let (r, _) = r.read_message(first).unwrap();
    let mut second = [0; 96];
    let request = r.write_message([2; 32], b"", &mut second).unwrap();
    let before = ERASED.get();
    let future = async move {
        let result = std::future::pending::<DhResult<C>>().await;
        request.resume(result)
    };
    let mut future = Box::pin(future);
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    assert_eq!(ERASED.get(), before + 1);
    second.fill(0); // The cancelled request also released its exclusive borrow.
}

#[test]
fn wrong_prologue_and_tampered_static_are_rejected() {
    let v = fixture("XX", "SHA256");
    let prologue = bytes(&v.init_prologue);
    for tamper in [false, true] {
        seed(&v);
        let i = XX::initiator::<C>(if tamper { &prologue } else { b"wrong" }).unwrap();
        let (i, _) = i
            .write_message(&bytes(&v.messages[0].payload), &mut [0; 64])
            .unwrap();
        let mut second = bytes(&v.messages[1].ciphertext);
        if tamper {
            second[32] ^= 1;
        }
        assert!(matches!(i.read_message(&mut second), Err(Error::Crypto)));
    }
}

// A real software backend must also work, independently of fixture injection.
#[test]
fn software_backend_empty_xx() {
    type Software = typestate_noise::crypto::DefaultCrypto;
    let si = StaticSecret::random();
    let sr = StaticSecret::random();
    let i = XX::initiator::<Software>(b"").unwrap();
    let r = XX::responder::<Software>(b"").unwrap();
    let mut first = [0; 32];
    let (i, wire) = i.write_message(b"", &mut first).unwrap();
    let (r, payload) = r.read_message(wire).unwrap();
    assert!(payload.is_empty());
    let mut second = [0; 96];
    let request = r
        .write_message(PublicKey::from(&sr).to_bytes(), b"", &mut second)
        .unwrap();
    let shared = DhResult::new(
        sr.diffie_hellman(&(*request.peer_public_key()).into())
            .to_bytes(),
    );
    let (r, wire) = request.resume(shared).unwrap();
    let (i, _) = i.read_message(wire).unwrap();
    let mut third = [0; 64];
    let request = i
        .write_message(PublicKey::from(&si).to_bytes(), b"", &mut third)
        .unwrap();
    let shared = DhResult::new(
        si.diffie_hellman(&(*request.peer_public_key()).into())
            .to_bytes(),
    );
    let (i, wire) = request.resume(shared).unwrap();
    let (r, _) = r.read_message(wire).unwrap();
    assert_eq!(i.handshake_hash(), r.handshake_hash());
}
