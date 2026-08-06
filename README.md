# edhoc

Ruby bindings for the complete EDHOC protocol surface provided by libedhoc's
built-in cryptography. Version 1.0 is a breaking redesign around
`Edhoc::Session`.

The supported platforms are macOS and Linux with Ruby 3.4 or newer. Windows is
not a supported or tested platform.

## Protocol support

- EDHOC authentication methods 0, 1, 2, and 3
- Cipher suites 0, 2, 4, and 24
- One to three offered cipher suites, in application preference order
- Messages 1–3 and optional message 4
- KID, x5chain, and x5t credentials with application-defined authentication
- Explicit X.509 trust through `OpenSSL::X509::Store`
- EAD callbacks for messages 1–4, including critical labels
- Protocol error messages and wrong-suite retry
- Raw exporters, key update, and direct OSCORE context export
- EDHOC-over-CoAP framing helpers and diagnostic snapshots

PQ suite -24, custom crypto backends, secure-element handles, Zephyr
integration, and logging backends are outside this gem's scope.

## Installation

Until the gem is published, install it from GitHub:

```ruby
gem 'edhoc', github: 'rsmp-nordic/ruby-edhoc'
```

The native extension requires Ruby development headers, CMake, and a C
compiler. libedhoc and its required external projects are included under
`vendor/libedhoc`, so users do not need to initialize submodules.

```sh
bundle install
bundle exec rake compile
bundle exec sus
bundle exec rubocop
```

## Credentials

Applications provide two callbacks. `select_local` chooses the key and
identification for the current role, method, suite, and message.
`authenticate_peer` applies application trust policy and returns `nil` to
reject a peer.

```ruby
class Credentials
  def initialize(local_key:, local_certificate:, peers:)
    @local_key = local_key
    @local_certificate = local_certificate
    @peers = peers
  end

  def select_local(context)
    Edhoc::LocalCredential.new(
      private_key: @local_key,
      identification: Edhoc::Credentials::X5Chain.new(
        certificates: [@local_certificate]
      )
    )
  end

  def authenticate_peer(context, received)
    certificate = received.certificates&.first
    peer = @peers[certificate]
    return unless peer

    Edhoc::TrustedCredential.new(
      credential: certificate,
      public_key: OpenSSL::X509::Certificate.new(certificate).public_key,
      peer_id: peer
    )
  end
end
```

The callback context exposes `role`, `method`, `suite` (also
`cipher_suite`), `message`, and `authentication`, where authentication is
`:signature` or `:static_dh`.

Credential identification values are:

```ruby
Edhoc::Credentials::KID.new(
  identifier: 'site-1', credential: credential_bytes, format: :raw
)

Edhoc::Credentials::KID.new(
  identifier: 'site-1', credential: encoded_ccs, format: :cbor
)

Edhoc::Credentials::X5Chain.new(certificates: [leaf, intermediate])

Edhoc::Credentials::X5T.new(
  algorithm: -15, fingerprint: sha256_64, certificate: leaf
)
```

Raw byte strings and `OpenSSL::PKey` objects are accepted. Raw key forms are:

| Suites | Authentication | Private key | Peer public key |
| --- | --- | --- | --- |
| 0/4 | signature | 32-byte Ed25519 seed or validated 64-byte seed + public | 32-byte Ed25519 |
| 0/4 | static DH | 32-byte X25519 | 32-byte X25519 |
| 2 | signature | 32-byte P-256 scalar | 65-byte uncompressed point |
| 2 | static DH | 32-byte P-256 scalar | 32-byte x-coordinate or 33-byte SEC1 compressed point |
| 24 | signature | 48-byte P-384 scalar | 97-byte uncompressed point |
| 24 | static DH | 48-byte P-384 scalar | 48-byte x-coordinate or 49-byte SEC1 compressed point |

### X.509 trust

`Credentials::X509Provider` requires an explicit trust store. It validates the
certificate path, validity period, thumbprint, suite-compatible key, and key
usage. A resolver can look up KID or x5t references, and a policy callback can
reject a verified peer or return an application peer ID.

```ruby
store = OpenSSL::X509::Store.new
store.add_cert(root_ca)

provider = Edhoc::Credentials::X509Provider.new(
  store: store,
  local: Edhoc::LocalCredential.new(
    private_key: local_key,
    identification: Edhoc::Credentials::X5Chain.new(
      certificates: [local_certificate, intermediate]
    )
  ),
  resolver: ->(context, received) { certificate_directory.resolve(received) },
  policy: ->(context, received, chain) { peer_id_for(chain.first) }
)
```

libedhoc deliberately delegates trust and revocation decisions to the
application. The provider does not silently use the operating system trust
store.

## Handshake

Preferences are most-preferred first. Methods must be unique values from 0–3;
cipher suites must be one to three unique values from 0, 2, 4, and 24.

```ruby
initiator = Edhoc::Session.new(
  role: :initiator,
  methods: [0, 2],
  cipher_suites: [24, 2, 0],
  connection_id: -14,
  credentials: initiator_credentials
)

responder = Edhoc::Session.new(
  role: :responder,
  methods: [0, 1, 2, 3],
  cipher_suites: [24, 2, 0],
  connection_id: "\x18".b,
  credentials: responder_credentials
)

responder.process_message1(initiator.compose_message1)
initiator.process_message2(responder.compose_message2)
responder.process_message3(initiator.compose_message3)

# Optional explicit key confirmation:
initiator.process_message4(responder.compose_message4)
```

`Suite0Session` and `Suite4Session` are convenience presets using the same
constructor, except that `cipher_suites:` is fixed and omitted:

```ruby
Edhoc::Suite4Session.new(
  role: :initiator, methods: [0], connection_id: -14,
  credentials: initiator_credentials
)
```

Calls are checked against the session role and state. A protocol failure moves
the session to `:aborted`; `close` is idempotent and moves it to `:closed`.

## EAD

An EAD handler implements `compose`, `process`, and `supports?`. Label-only
tokens remain distinct from tokens containing an explicitly empty byte string.
Negative labels are critical; the receiving handler must recognize their
absolute value.

```ruby
class EadHandler
  def compose(context)
    [Edhoc::EAD::Token.new(label: 10, value: authorization_data)]
  end

  def process(context, tokens)
    tokens.each { |token| authorize(token) }
  end

  def supports?(label)
    label == 10
  end
end
```

Each message can carry up to three EAD tokens.

## Negotiation errors and retry

```ruby
begin
  responder.process_message1(message_1)
rescue Edhoc::MessageError
  bytes = responder.error_message.to_bytes
end

error = initiator.process_error_message(bytes)
if error.code == :wrong_selected_cipher_suite
  retry_suites = initiator.cipher_suites & error.cipher_suites
  initiator.restart!(cipher_suites: retry_suites.take(3))
end
```

`ErrorMessage.parse` and `#to_bytes` support success, unspecified error, wrong
selected cipher suite, and unknown credential referenced.

## Exporters and OSCORE

Exporters are available after message 3:

```ruby
secret = initiator.export(label: 32_768, context: application_context, length: 32)

oscore = initiator.export_oscore_context(
  master_secret_length: 16,
  master_salt_length: 8
)
oscore.master_secret
oscore.master_salt
oscore.sender_id
oscore.recipient_id

initiator.key_update!('next epoch')
next_oscore = initiator.export_oscore_context
```

OSCORE export is one-shot until `key_update!` succeeds. `OscoreContext#destroy!`
overwrites its Ruby secret strings as a best effort.

The extension zeroizes native secret and transient key buffers and destroys
volatile PSA handles on failure, restart, close, and finalization. It cannot
reliably zeroize caller-owned Ruby strings or OpenSSL objects.

## CoAP and diagnostics

```ruby
payload = Edhoc::CoAP.prepend_flow(message_1)
flow = Edhoc::CoAP.extract_flow(payload)

payload = Edhoc::CoAP.prepend_connection_id(message_3, connection_id)
parts = Edhoc::CoAP.extract_connection_id(payload)
Edhoc::CoAP.connection_id_equal?(parts[:connection_id], connection_id)

snapshot = initiator.diagnostics
snapshot.state
snapshot.selected_method
snapshot.selected_cipher_suite
snapshot.peer_cipher_suites
snapshot.native_error_code
snapshot.protocol_error_code
```

Native errors are subclasses of `Edhoc::NativeError` and expose `operation`,
symbolic `code`, numeric `code_number`, `protocol_code`, and local/peer suite
lists.

## Updating vendored libedhoc

The exact upstream and external commits are recorded in
`vendor/libedhoc/ruby-edhoc-vendor.yml`. Update from the recorded ref, or an
explicit ref, with:

```sh
bundle exec rake vendor:update
bundle exec rake 'vendor:update[v2.0.1]'
```

The task refuses a dirty worktree, regenerates the packaged Mbed TLS/TF-PSA
sources, verifies and applies every patch under `patches/libedhoc`, and updates
the metadata. Maintainers need Perl, Python 3, and the TF-PSA generator packages.

Confirmed upstream behavior relevant to the binding is recorded in
[`LIBEDHOC_FINDINGS.md`](LIBEDHOC_FINDINGS.md).

The Ruby wrapper and vendored libedhoc project are MIT licensed. See
`LICENSE.txt` and `vendor/libedhoc/LICENSE`.
