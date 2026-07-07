# edhoc

Experimental Ruby bindings for [libedhoc](https://github.com/kamil-kielbasa/libedhoc).

This first version targets the Secure RSMP draft profile work:

- EDHOC method 0
- EDHOC cipher suite 0
- X25519 ephemeral key agreement
- Ed25519 / EdDSA authentication
- X.509-chain credential transport

The current Secure RSMP proposal discusses X25519/Ed25519 with ChaCha20-Poly1305. `libedhoc` does not currently expose that exact EDHOC cipher suite; suite 0 is the closest supported profile because it uses method 0, X25519, EdDSA, and SHA-256, but AES-CCM-16-64-128 for EDHOC AEAD. This gem is therefore a working integration spike and conformance-tooling base, not yet the final RSMP mandatory profile.

The public API is intentionally narrow while the native boundary settles.

```ruby
initiator = Edhoc::Suite0Session.new(
  role: :initiator,
  private_key: initiator_private_key,
  credential: initiator_certificate_der,
  peer_public_key: responder_public_key,
  peer_credential: responder_certificate_der
)

responder = Edhoc::Suite0Session.new(
  role: :responder,
  private_key: responder_private_key,
  credential: responder_certificate_der,
  peer_public_key: initiator_public_key,
  peer_credential: initiator_certificate_der
)

m1 = initiator.compose_message1
responder.process_message1(m1)
m2 = responder.compose_message2
initiator.process_message2(m2)
m3 = initiator.compose_message3
responder.process_message3(m3)
```

## Build

The native extension requires:

- Ruby development headers
- CMake
- a C compiler

`libedhoc` is vendored under `vendor/libedhoc`. Its required submodules must be present:

```sh
cd vendor/libedhoc
git submodule update --init --depth 1 externals/mbedtls externals/zcbor externals/compact25519 externals/Unity
```

Then:

```sh
bundle install
bundle exec rake compile
bundle exec rake test
```

## Status

This is not yet a full general-purpose EDHOC API. It is a first binding for the proposed Secure RSMP profile and conformance tooling.
