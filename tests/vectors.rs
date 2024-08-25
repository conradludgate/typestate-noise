use bytes::BytesMut;
use libtest_mimic::{Arguments, Failed, Trial};
use serde::Deserialize;
use typestate_noise::{hlist, Ee, Es, HandshakeState, Recv, Se, Send, Ss, E, S};
use x25519_dalek::StaticSecret;

#[derive(Deserialize)]
struct Messages {
    ciphertext: String,
    payload: String,
}

#[derive(Deserialize)]
struct Vectors {
    protocol_name: String,

    init_static: Option<String>,
    init_ephemeral: String,
    init_prologue: String,
    init_psks: Vec<String>,
    init_remote_static: Option<String>,
    messages: Vec<Messages>,
    resp_ephemeral: String,
    resp_prologue: String,
    resp_psks: Vec<String>,
    resp_static: Option<String>,
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
            #[cfg(typestate_noise_vectors)]
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

#[cfg(typestate_noise_vectors)]
fn ik(test: Vectors) -> Result<(), Failed> {
    type IkPre0 = hlist![S];
    type IkMsg0 = hlist![E, Es, S, Ss];
    type IkMsg1 = hlist![E, Ee, Se];

    let hs_init = HandshakeState::initiator(&test.protocol_name)
        .with_static_key(StaticSecret::from(
            <[u8; 32]>::try_from(hex::decode(test.init_static.unwrap()).unwrap()).unwrap(),
        ))
        .with_ephemeral_key(StaticSecret::from(
            <[u8; 32]>::try_from(hex::decode(test.init_ephemeral).unwrap()).unwrap(),
        ));
    let hs_resp = HandshakeState::responder(&test.protocol_name)
        .with_static_key(StaticSecret::from(
            <[u8; 32]>::try_from(hex::decode(test.resp_static.unwrap()).unwrap()).unwrap(),
        ))
        .with_ephemeral_key(StaticSecret::from(
            <[u8; 32]>::try_from(hex::decode(test.resp_ephemeral).unwrap()).unwrap(),
        ));

    let mut msg = vec![];
    let hs_resp = IkPre0::send(&mut msg, hs_resp);
    let hs_init = IkPre0::recv(&mut BytesMut::from(&*msg), hs_init).map_err(|e| Failed::from(e))?;

    let mut msg = vec![];
    let hs_init = IkMsg0::send(&mut msg, hs_init);
    let hs_resp = IkMsg0::recv(&mut BytesMut::from(&*msg), hs_resp).map_err(|e| Failed::from(e))?;

    let mut msg = vec![];
    let hs_resp = IkMsg1::send(&mut msg, hs_resp);
    let hs_init = IkMsg1::recv(&mut BytesMut::from(&*msg), hs_init).map_err(|e| Failed::from(e))?;

    assert_eq!(hs_init.cipher.k.0, hs_resp.cipher.k.0);
    assert_eq!(hs_init.symm.ck, hs_resp.symm.ck);
    assert_eq!(hs_init.symm.h, hs_resp.symm.h);

    Ok(())
}
