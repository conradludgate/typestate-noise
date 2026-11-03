//! Run with `cargo run --example xx`.
use typestate_noise::{
    crypto::DefaultCrypto,
    handshake::{DhResult, Error, XX},
};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<(), Error> {
    // These keys belong to the application, not the Noise core. A real application
    // can keep them in an HSM and await its DH operation at each request below.
    let initiator_key = StaticSecret::random();
    let responder_key = StaticSecret::random();
    let initiator = XX::initiator::<DefaultCrypto>(b"example")?;
    let responder = XX::responder::<DefaultCrypto>(b"example")?;

    let mut message1 = [0; 128];
    let (initiator, wire) = initiator.write_message(b"hello", &mut message1)?;
    let (responder, _) = responder.read_message(wire)?;

    let mut message2 = [0; 128];
    let request = responder.write_message(
        PublicKey::from(&responder_key).to_bytes(),
        b"hello back",
        &mut message2,
    )?;
    let shared = responder_key.diffie_hellman(&(*request.peer_public_key()).into());
    let (responder, wire) = request.resume(DhResult::new(shared.to_bytes()))?;
    let (initiator, _) = initiator.read_message(wire)?;

    let mut message3 = [0; 128];
    let request = initiator.write_message(
        PublicKey::from(&initiator_key).to_bytes(),
        b"ready",
        &mut message3,
    )?;
    let shared = initiator_key.diffie_hellman(&(*request.peer_public_key()).into());
    let (mut initiator, wire) = request.resume(DhResult::new(shared.to_bytes()))?;
    let (mut responder, _) = responder.read_message(wire)?;

    // Validate responder.remote_static() against application identity policy here.
    let mut transport = [0; 21];
    transport[..5].copy_from_slice(b"hello");
    let wire = initiator.encrypt(&mut transport)?;
    let plaintext = responder.decrypt(wire)?;
    println!("{}", String::from_utf8_lossy(plaintext));
    Ok(())
}
