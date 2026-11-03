# typestate-noise

An experimental Rust implementation of Noise with compile-time handshake sequencing.

The new API is in `typestate_noise::handshake`; the original token-list API remains
available at the crate root. This first implementation supports **XX** and **IK**,
without PSK modifiers or fallback negotiation.

- One boxed core stays at the same address through handshake steps, external DH
  requests and transport mode. Ephemeral secrets and symmetric secrets use
  zeroizing owners; completing a handshake drops its ephemeral secret and erases
  its chaining key.
- Crypto suites select independent `Dh`, `Cipher` and `Hash` implementations with
  associated key/output types and sizes. Built-in primitives are X25519,
  ChaChaPoly, SHA256 and SHA512. `DefaultCrypto` selects SHA256.
- Static private keys never enter the core. Supply public credentials where the
  pattern requires them, then answer typed `DhRequest`s using application code.
  A request exposes its local static public key and the exact peer public key.
- Each state exposes only its next read or write operation. Completion returns a
  `Transport`; there is no premature finish operation or runtime pattern parser.
- The in-place message API borrows caller-owned buffers. The copying convenience
  API uses the same transitions. Neither allocates a message buffer internally.

Run a complete exchange with:

```sh
cargo run --example xx
```

For an asynchronous static key service, a responder's XX message 2 looks like:

```rust,ignore
let request = responder.write_message(local_public_key, payload, &mut output)?;
let shared = hsm.x25519(request.local_public_key(), request.peer_public_key()).await?;
let (responder, wire) = request.resume(DhResult::new(shared))?;
```

`local_public_key()` identifies the credential used for this handshake; the
application must use the corresponding private key and return the correct DH
result. The core does not depend on an HSM client, executor, or future type.
Dropping an outstanding request abandons the handshake and releases its buffer.

For `write_message_in_place`, place plaintext at that sending state's
`PAYLOAD_OFFSET` and reserve `OVERHEAD + payload_length` bytes in total. Writes
return the encoded message slice; reads return a slice of authenticated plaintext
(except XX's first payload, which is unencrypted and unauthenticated). Reads take
exactly one complete, externally framed Noise message, with a maximum of 65535
bytes. Handshake failures consume the state. Failed in-place decryption may modify
the buffer; its contents must not be treated as authenticated plaintext.

A completed XX or IK handshake authenticates possession of the participating
static keys. The application still decides whether the remote public key is a
trusted identity. Crypto backends are trusted implementations of their advertised
algorithms, lengths and freshness requirements. Unchecked private accessors rely
on sealed transitions to prove field initialization; `Option` retains automatic
cleanup on early returns and unwinding.

Tests compare both patterns byte for byte with the bundled Noise vectors using
SHA256 and SHA512, and interoperate with Snow for transport messages in both
directions. They also check message ordering at compile time, in-place operation,
malformed input, authentication failures, nonce handling, and cancellation cleanup.
