# edhoc

Experimental Ruby bindings for [libedhoc](https://github.com/kamil-kielbasa/libedhoc).

This gem exists to support Secure RSMP prototype work and RSMP conformance tooling. It is not yet a
general-purpose EDHOC library.

## Supported Profiles

The current public API exposes two EDHOC method 0 profiles:

| Ruby class | EDHOC cipher suite | Key agreement | Authentication | EDHOC AEAD |
| --- | --- | --- | --- | --- |
| `Edhoc::Suite0Session` | 0 | X25519 | Ed25519 / EdDSA | AES-CCM-16-64-128 |
| `Edhoc::Suite4Session` | 4 | X25519 | Ed25519 / EdDSA | ChaCha20-Poly1305 |

Both profiles currently use X.509-chain credential transport through libedhoc.

## Installation

This gem is currently developed locally inside the RSMP workspace. Use it from another Gemfile with a
path dependency:

```ruby
gem 'edhoc', path: '../ruby-edhoc'
```

The native extension requires:

- Ruby development headers
- CMake
- a C compiler

`libedhoc` is vendored under `vendor/libedhoc`. Its required submodules must be present:

```sh
cd vendor/libedhoc
git submodule update --init --depth 1 externals/mbedtls externals/zcbor externals/compact25519 externals/Unity
```

Build and test:

```sh
bundle install
bundle exec rake compile
bundle exec sus
bundle exec rubocop
```

## Basic Handshake

```ruby
require 'edhoc'

initiator = Edhoc::Suite4Session.new(
  role: :initiator,
  private_key: initiator_private_key,
  credential: initiator_certificate_der,
  peer_public_key: responder_public_key,
  peer_credential: responder_certificate_der
)

responder = Edhoc::Suite4Session.new(
  role: :responder,
  private_key: responder_private_key,
  credential: responder_certificate_der,
  peer_public_key: initiator_public_key,
  peer_credential: initiator_certificate_der
)

message1 = initiator.compose_message1
responder.process_message1(message1)

message2 = responder.compose_message2
initiator.process_message2(message2)

message3 = initiator.compose_message3
responder.process_message3(message3)

secret = initiator.export_prk(0, 32)
```

Always close sessions when done:

```ruby
initiator.close
responder.close
```

## Multi-Peer Responder

A responder can be configured with multiple trusted peers. The native verifier matches the presented
credential against the configured set and exposes the matched peer id after the handshake.

```ruby
responder = Edhoc::Suite0Session.new(
  role: :responder,
  private_key: responder_private_key,
  credential: responder_certificate_der,
  peers: [
    {
      id: 'RN+SI0001',
      public_key: site1_public_key,
      credential: site1_certificate_der
    },
    {
      id: 'RN+SI0002',
      public_key: site2_public_key,
      credential: site2_certificate_der
    }
  ]
)

# After process_message3 succeeds:
responder.matched_peer_id
```

If a peer presents an X.509 credential that is not trusted, `process_message3` raises
`Edhoc::CredentialsError`. When possible, the error message includes the credential common name:

```text
peer credential RN+SI0002 not trusted
```

## Native Errors

libedhoc failures are mapped to Ruby exceptions under `Edhoc::Error`, including typed subclasses such
as `Edhoc::BadStateError` and `Edhoc::CredentialsError`.

## Development Status

This gem deliberately keeps the public API small while the native boundary settles. It is suitable for
local Secure RSMP prototype testing, but it should not be treated as a production-ready credential
system.

The Ruby wrapper is MIT licensed. The vendored `libedhoc` project is also MIT licensed; see
`vendor/libedhoc/LICENSE`.
