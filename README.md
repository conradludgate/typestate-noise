# typestate-noise

An experimental Rust implementation of Noise with compile-time handshake sequencing.

The new API is in `typestate_noise::handshake`; the original token-list API remains
available at the crate root. The new API supports **XX** and **IK**, with optional
**PSK0**, **PSK2**, or **PSK0+PSK2** modifiers. Fallback negotiation is not implemented.

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

## Pre-shared keys

Use the appropriate constructor on `XX` or `IK`:

| Modifier | Initiator / responder constructors | When to supply the PSK |
| --- | --- | --- |
| None | `initiator` / `responder` | No PSK |
| PSK0 | `initiator_psk0` / `responder_psk0` | Required `Psk` constructor argument |
| PSK2 | `initiator_psk2` / `responder_psk2` | `PskRequest::provide_psk` in message 2 |
| PSK0+PSK2 | `initiator_psk0_psk2` / `responder_psk0_psk2` | One at construction, another in message 2 |

`Psk::new` takes exactly `[u8; 32]`, independently of the DH/hash output lengths.
It is consumed and erased at its token; PSKs are never retained in the core.
PSK2 requests can be held across an await to look up a key. Where the peer static
key is already available, `remote_static()` exposes it for key selection. Identity
and PSK possession are not confirmed until the required authentication succeeds.
The XX responder has not received the initiator's static key at this point, so it
must choose its PSK2 from application context.

For example, an XX PSK2 responder pauses for DH and then for its PSK:

```rust,ignore
let dh = responder.write_message(local_public_key, payload, &mut output)?;
let shared = hsm.x25519(dh.local_public_key(), dh.peer_public_key()).await?;
let psk_request = dh.resume(DhResult::new(shared))?;
let (responder, wire) = psk_request.provide_psk(Psk::new(psk_bytes))?;
```

Run the complete PSK2 exchange with `cargo run --example xx_psk2`.

Every PSK mode applies `MixKey` to every ephemeral public key, even before a PSK2
token is reached. XX's first message therefore includes an encrypted-payload tag
in all PSK modes. With PSK2 alone this provides no peer authentication or useful
payload secrecy, because the PSK has not been mixed yet. With PSK0, that first
payload is protected by the PSK, without forward secrecy. The selected mode is a
sealed type parameter; the original non-PSK API keeps its method signatures and
wire format.

For `write_message_in_place`, place plaintext at that sending state's
`PAYLOAD_OFFSET` and reserve `OVERHEAD + payload_length` bytes in total. Writes
return the encoded message slice; reads return a slice of authenticated plaintext
(except unmodified XX's first payload, which is unencrypted and unauthenticated;
PSK2-only XX also has no peer authentication for its first payload). Reads take
exactly one complete, externally framed Noise message, with a maximum of 65535
bytes. Handshake failures consume the state. Failed in-place decryption may modify
the buffer; its contents must not be treated as authenticated plaintext.

A completed XX or IK handshake authenticates possession of the participating
static keys. The application still decides whether the remote public key is a
trusted identity. Crypto backends are trusted implementations of their advertised
algorithms, lengths and freshness requirements. Unchecked private accessors rely
on sealed transitions to prove field initialization; `Option` retains automatic
cleanup on early returns and unwinding.

Tests compare unmodified and combined PSK0+PSK2 handshakes byte for byte with the
bundled Noise vectors using SHA256 and SHA512. Individual PSK0/PSK2 cases compare
against Snow, including final handshake hashes and transport messages in both
directions. Tests also check message ordering and required PSKs at compile time,
in-place operation, malformed input, authentication failures, nonce handling, and
cancellation cleanup.
