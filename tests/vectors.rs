#![allow(dead_code, unused_imports)]

use std::ops::Deref;

use bytes::{Bytes, BytesMut};
use libtest_mimic::{Arguments, Failed, Trial};
use serde::Deserialize;
use typestate_noise::{hlist, Ee, Es, HandshakeState, Recv, Se, Send, Ss, E, S};
use x25519_dalek::StaticSecret;

struct Hex(Bytes);

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(s).map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(Hex(Bytes::from(v)))
    }
}

impl Deref for Hex {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Deserialize)]
struct Messages {
    ciphertext: Hex,
    payload: Hex,
}

#[derive(Deserialize)]
struct Vectors {
    protocol_name: String,

    init_static: Option<Hex>,
    init_ephemeral: Hex,
    init_prologue: Hex,
    init_psks: Vec<Hex>,
    init_remote_static: Option<Hex>,

    resp_static: Option<Hex>,
    resp_ephemeral: Hex,
    resp_prologue: Hex,
    resp_psks: Vec<Hex>,

    messages: Vec<Messages>,
}

#[derive(Deserialize)]
struct Tests {
    vectors: Vec<Vectors>,
}

fn main() {
    let args = Arguments::from_args();

    let file = std::fs::read_to_string("tests/snow.json").unwrap();
    let tests: Tests = serde_json::from_str(&file).unwrap();

    let mut trials = vec![];
    for (i, test) in tests.vectors.into_iter().enumerate() {
        match test.protocol_name.as_str() {
            #[cfg(unsafe_typestate_noise_vectors)]
            "Noise_IK_25519_ChaChaPoly_SHA256" => trials
                .push(Trial::test(format!("{}::{i}", test.protocol_name), || {
                    ik(test)
                })),
            _ => trials.push(
                Trial::test(format!("{}::{i}", test.protocol_name), || {
                    Err(Failed::without_message())
                })
                .with_ignored_flag(true),
            ),
        }
    }

    libtest_mimic::run(&args, trials).exit();
}

#[cfg(unsafe_typestate_noise_vectors)]
fn ik(test: Vectors) -> Result<(), Failed> {
    use typestate_noise::{Payload, RecvPreMsg, RecvWithPayload, SendPreMsg, SendWithPayload};

    type IkPre0 = hlist![S];
    type IkMsg0 = hlist![E, Es, S, Ss, Payload];
    type IkMsg1 = hlist![E, Ee, Se, Payload];

    assert!(test.init_psks.is_empty());
    assert!(test.resp_psks.is_empty());

    let hs_init = {
        let hs_init = HandshakeState::initiator(&test.protocol_name)
            .with_static_key(StaticSecret::from(
                <[u8; 32]>::try_from(&*test.init_static.unwrap()).unwrap(),
            ))
            .with_ephemeral_key(StaticSecret::from(
                <[u8; 32]>::try_from(&*test.init_ephemeral).unwrap(),
            ))
            .with_prologue(&test.init_prologue);

        let mut msg = BytesMut::from(test.init_remote_static.unwrap().0);
        let hs_init = IkPre0::recv_premsg(&mut msg, hs_init).map_err(Failed::from)?;

        let mut msg = BytesMut::new();
        let hs_init = IkMsg0::send_with_payload(&mut msg, hs_init, &test.messages[0].payload);
        assert_eq!(test.messages[0].ciphertext.0, msg.freeze(), "msg0 init");

        let mut msg = BytesMut::from(test.messages[1].ciphertext.0.clone());
        let (hs_init, payload) =
            IkMsg1::recv_with_payload(&mut msg, hs_init).map_err(Failed::from)?;
        assert_eq!(test.messages[1].payload.0, payload.freeze(), "msg1 init");
        hs_init
    };

    let hs_resp = {
        let hs_resp = HandshakeState::responder(&test.protocol_name)
            .with_static_key(StaticSecret::from(
                <[u8; 32]>::try_from(&*test.resp_static.unwrap()).unwrap(),
            ))
            .with_ephemeral_key(StaticSecret::from(
                <[u8; 32]>::try_from(&*test.resp_ephemeral).unwrap(),
            ))
            .with_prologue(&test.resp_prologue);

        let mut msg = BytesMut::new();
        let hs_resp = IkPre0::send_premsg(&mut msg, hs_resp);

        let mut msg = BytesMut::from(test.messages[0].ciphertext.0.clone());
        let (hs_resp, payload) =
            IkMsg0::recv_with_payload(&mut msg, hs_resp).map_err(Failed::from)?;
        assert_eq!(test.messages[0].payload.0, payload.freeze(), "msg0 resp");

        let mut msg = BytesMut::new();
        let hs_resp = IkMsg1::send_with_payload(&mut msg, hs_resp, &test.messages[1].payload);
        assert_eq!(test.messages[1].ciphertext.0, msg.freeze(), "msg1 resp");

        hs_resp
    };

    assert_eq!(hs_init.cipher.k.0, hs_resp.cipher.k.0);
    assert_eq!(hs_init.symm.ck, hs_resp.symm.ck);
    assert_eq!(hs_init.symm.h, hs_resp.symm.h);

    Ok(())
}
