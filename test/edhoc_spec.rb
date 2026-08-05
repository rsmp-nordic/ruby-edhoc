require_relative 'test_helper'
require 'openssl'

describe Edhoc do
  def generated_identity(id)
    key = OpenSSL::PKey.generate_key('ED25519')
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = OpenSSL::X509::Name.new([['CN', id, OpenSSL::ASN1::UTF8STRING]])
    certificate.issuer = certificate.subject
    certificate.public_key = key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.sign(key, nil)

    {
      private_key: key.raw_private_key + key.raw_public_key,
      public_key: key.raw_public_key,
      credential: certificate.to_der
    }
  end

  def suite0_sessions(vector)
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )

    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peer_public_key: vector.fetch(:initiator_public_key),
      peer_credential: vector.fetch(:initiator_credential)
    )

    [initiator, responder]
  end

  def suite4_sessions(vector)
    initiator = Edhoc::Suite4Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )

    responder = Edhoc::Suite4Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peer_public_key: vector.fetch(:initiator_public_key),
      peer_credential: vector.fetch(:initiator_credential)
    )

    [initiator, responder]
  end

  def kid_cbor_suite4_sessions(vector)
    [kid_cbor_suite4_initiator(vector), kid_cbor_suite4_responder(vector)]
  end

  def kid_cbor_suite4_initiator(vector)
    Edhoc::Suite4Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: "\xA1\x62id\x64site".b,
      credential_format: :kid_cbor,
      kid: 'site-kid',
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: "\xA1\x62id\x6Asupervisor".b,
      peer_kid: 'supervisor-kid'
    )
  end

  def kid_cbor_suite4_responder(vector)
    Edhoc::Suite4Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: "\xA1\x62id\x6Asupervisor".b,
      credential_format: :kid_cbor,
      kid: 'supervisor-kid',
      peers: [
        {
          id: 'site-a',
          public_key: vector.fetch(:initiator_public_key),
          credential: "\xA1\x62id\x64site".b,
          kid: 'site-kid'
        }
      ]
    )
  end

  def run_suite0_handshake(initiator, responder)
    message1 = initiator.compose_message1
    expect(message1.bytesize).to be > 0
    expect(responder.process_message1(message1)).to be == true

    message2 = responder.compose_message2
    expect(message2.bytesize).to be > 0
    expect(initiator.process_message2(message2)).to be == true

    message3 = initiator.compose_message3
    expect(message3.bytesize).to be > 0
    expect(responder.process_message3(message3)).to be == true
  end

  it 'reports the libedhoc v2 API version' do
    expect(Edhoc::Native.library_version).to be == {
      libedhoc_api_major: 2,
      libedhoc_api_minor: 0,
      libedhoc_api_patch: 0
    }
  end

  it 'exposes native profile metadata for the secure RSMP candidate' do
    profile = Edhoc::Native.suite0_profile

    expect(profile.fetch(:method)).to be == 0
    expect(profile.fetch(:cipher_suite)).to be == 0
    expect(profile.fetch(:ecdh)).to be == 'X25519'
    expect(profile.fetch(:signature)).to be == 'Ed25519/EdDSA'
    expect(profile.fetch(:hash)).to be == 'SHA-256'
  end

  it 'exposes native profile metadata for EDHOC suite 4' do
    profile = Edhoc::Native.suite4_profile

    expect(profile.fetch(:method)).to be == 0
    expect(profile.fetch(:cipher_suite)).to be == 4
    expect(profile.fetch(:ecdh)).to be == 'X25519'
    expect(profile.fetch(:signature)).to be == 'Ed25519/EdDSA'
    expect(profile.fetch(:hash)).to be == 'SHA-256'
    expect(profile.fetch(:aead)).to be == 'ChaCha20-Poly1305'
    expect(profile.fetch(:aead_key_length)).to be == 32
    expect(profile.fetch(:aead_tag_length)).to be == 16
    expect(profile.fetch(:aead_iv_length)).to be == 12
  end

  it 'runs a suite 0 initiator/responder handshake' do
    vector = Edhoc::TestVector.suite0
    initiator, responder = suite0_sessions(vector)
    run_suite0_handshake(initiator, responder)

    initiator_secret = initiator.export_prk(0, 16)
    responder_secret = responder.export_prk(0, 16)

    expect(initiator_secret.bytesize).to be == 16
    expect(initiator_secret).to be == responder_secret
  ensure
    initiator&.close
    responder&.close
  end

  it 'runs a suite 4 initiator/responder handshake' do
    vector = Edhoc::TestVector.suite0
    initiator, responder = suite4_sessions(vector)
    run_suite0_handshake(initiator, responder)

    initiator_secret = initiator.export_prk(0, 32)
    responder_secret = responder.export_prk(0, 32)

    expect(initiator_secret.bytesize).to be == 32
    expect(initiator_secret).to be == responder_secret
  ensure
    initiator&.close
    responder&.close
  end

  it 'exports matching context-bound keying material' do
    vector = Edhoc::TestVector.suite0
    initiator, responder = suite4_sessions(vector)
    run_suite0_handshake(initiator, responder)
    context = 'rsmp-secure-v1 context'.b

    initiator_secret = initiator.export_prk_with_context(32_768, context, 32)
    responder_secret = responder.export_prk_with_context(32_768, context, 32)

    expect(initiator_secret).to be == responder_secret
    expect(initiator_secret.bytesize).to be == 32
    expect(initiator_secret).not.to be == initiator.export_prk_with_context(32_768, 'other context'.b, 32)
    expect(initiator.export_prk_with_context(32_768, ''.b, 32)).to be == initiator.export_prk(32_768, 32)
  ensure
    initiator&.close
    responder&.close
  end

  it 'runs a suite 4 handshake with kid-identified CBOR credentials' do
    vector = Edhoc::TestVector.suite0
    initiator, responder = kid_cbor_suite4_sessions(vector)
    run_suite0_handshake(initiator, responder)

    initiator_secret = initiator.export_prk(0, 32)
    responder_secret = responder.export_prk(0, 32)

    expect(initiator_secret.bytesize).to be == 32
    expect(initiator_secret).to be == responder_secret
    expect(responder.matched_peer_id).to be == 'site-a'
  ensure
    initiator&.close
    responder&.close
  end

  it 'matches a known peer from a responder peer set' do
    vector = Edhoc::TestVector.suite0
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )
    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peers: [
        {
          id: 'other-site',
          public_key: 'x' * 32,
          credential: 'not the initiator credential'
        },
        {
          id: 'site-a',
          public_key: vector.fetch(:initiator_public_key),
          credential: vector.fetch(:initiator_credential)
        }
      ]
    )

    run_suite0_handshake(initiator, responder)

    expect(responder.matched_peer_id).to be == 'site-a'
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects unknown peers in a responder peer set' do
    vector = Edhoc::TestVector.suite0
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )
    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peers: [
        {
          id: 'other-site',
          public_key: 'x' * 32,
          credential: 'not the initiator credential'
        }
      ]
    )

    responder.process_message1(initiator.compose_message1)
    initiator.process_message2(responder.compose_message2)

    expect do
      responder.process_message3(initiator.compose_message3)
    end.to raise_exception(Edhoc::CredentialsError)
  ensure
    initiator&.close
    responder&.close
  end

  it 'names an untrusted x509 credential by common name' do
    vector = Edhoc::TestVector.suite0
    site = generated_identity('RN+SI0002')
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: site.fetch(:private_key),
      credential: site.fetch(:credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )
    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peers: [
        {
          id: 'RN+SI0001',
          public_key: vector.fetch(:initiator_public_key),
          credential: vector.fetch(:initiator_credential)
        }
      ]
    )

    responder.process_message1(initiator.compose_message1)
    initiator.process_message2(responder.compose_message2)

    expect do
      responder.process_message3(initiator.compose_message3)
    end.to raise_exception(Edhoc::CredentialsError, message: be == 'peer credential RN+SI0002 not trusted')
  ensure
    initiator&.close
    responder&.close
  end

  it 'raises typed Ruby exceptions for native libedhoc failures' do
    vector = Edhoc::TestVector.suite0
    initiator, = suite0_sessions(vector)

    expect(Edhoc::NativeError < Edhoc::Error).to be == true
    expect(Edhoc::BadStateError < Edhoc::NativeError).to be == true

    error = nil
    begin
      initiator.export_prk(0, 16)
    rescue Edhoc::BadStateError => e
      error = e
    end

    expect(error).to be_a(Edhoc::BadStateError)
    expect(error.message).to be(:include?, 'bad_state (-104)')
  ensure
    initiator&.close
  end

  it 'rejects malformed message 1 input without entering the handshake' do
    vector = Edhoc::TestVector.suite0
    _, responder = suite4_sessions(vector)

    expect do
      responder.process_message1("\xFF".b)
    end.to raise_exception(Edhoc::CborError)
  ensure
    responder&.close
  end

  it 'rejects message 3 ciphertext shorter than the authentication tag' do
    vector = Edhoc::TestVector.suite0
    initiator, responder = suite4_sessions(vector)
    responder.process_message1(initiator.compose_message1)
    initiator.process_message2(responder.compose_message2)

    expect do
      responder.process_message3("\x40".b)
    end.to raise_exception(Edhoc::MessageError)
  ensure
    initiator&.close
    responder&.close
  end

  it 'releases imported PSA authentication keys when sessions close' do
    vector = Edhoc::TestVector.suite0

    64.times do
      initiator, responder = suite4_sessions(vector)
      initiator.close
      responder.close
    end
  end
end
