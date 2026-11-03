//! Run with `cargo run --example xx_psk2`.
use typestate_noise::{
    crypto::DefaultCrypto,
    handshake::{DhResult, Error, Psk, XX},
};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<(), Error> {
    // Demonstration credentials. Obtain independent production PSKs securely.
    let psk_bytes = [42; 32];
    let initiator_key = StaticSecret::random();
    let responder_key = StaticSecret::random();
    let initiator = XX::initiator_psk2::<DefaultCrypto>(b"example")?;
    let responder = XX::responder_psk2::<DefaultCrypto>(b"example")?;

    let mut message1 = [0; 128];
    let (initiator, wire) = initiator.write_message(b"hello", &mut message1)?;
    let (responder, _) = responder.read_message(wire)?;

    let mut message2 = [0; 128];
    let dh = responder.write_message(
        PublicKey::from(&responder_key).to_bytes(),
        b"hello back",
        &mut message2,
    )?;
    let shared = responder_key.diffie_hellman(&(*dh.peer_public_key()).into());
    let psk = dh.resume(DhResult::new(shared.to_bytes()))?;
    // In an async application, the request can await a PSK lookup here.
    let (responder, wire) = psk.provide_psk(Psk::new(psk_bytes))?;
    let psk = initiator.read_message(wire)?;
    assert_eq!(
        *psk.remote_static(),
        PublicKey::from(&responder_key).to_bytes()
    );
    let (initiator, _) = psk.provide_psk(Psk::new(psk_bytes))?;

    let mut message3 = [0; 128];
    let dh = initiator.write_message(
        PublicKey::from(&initiator_key).to_bytes(),
        b"ready",
        &mut message3,
    )?;
    let shared = initiator_key.diffie_hellman(&(*dh.peer_public_key()).into());
    let (mut initiator, wire) = dh.resume(DhResult::new(shared.to_bytes()))?;
    let (mut responder, _) = responder.read_message(wire)?;

    let mut transport = [0; 21];
    transport[..5].copy_from_slice(b"hello");
    let wire = initiator.encrypt(&mut transport)?;
    println!("{}", String::from_utf8_lossy(responder.decrypt(wire)?));
    Ok(())
}
