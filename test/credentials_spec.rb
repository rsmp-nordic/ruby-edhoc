require_relative 'test_helper'

class CapturingCredentialProvider
  attr_reader :received

  def initialize(key:, identification:, peer_key:, peer_credential:, peer_format:)
    @key = key
    @identification = identification
    @peer_key = peer_key
    @peer_credential = peer_credential
    @peer_format = peer_format
  end

  def select_local(_context)
    Edhoc::LocalCredential.new(private_key: @key, identification: @identification)
  end

  def authenticate_peer(_context, received)
    @received = received
    Edhoc::TrustedCredential.new(
      credential: @peer_credential, public_key: @peer_key,
      format: @peer_format
    )
  end
end

describe Edhoc::Credentials do
  include CertificateTestHelpers
  include SessionTestHelpers

  it 'performs a handshake with an explicit X.509 store and application policy' do
    root, initiator_key, initiator_certificate, responder_key, responder_certificate = x509_pair
    store = OpenSSL::X509::Store.new
    store.add_cert(root)
    policy = lambda do |_context, _received, chain|
      chain.first.subject.to_a.find { |name,| name == 'CN' }.fetch(1)
    end
    initiator_provider = Edhoc::Credentials::X509Provider.new(
      store: store,
      local: Edhoc::LocalCredential.new(
        private_key: initiator_key,
        identification: Edhoc::Credentials::X5Chain.new(certificates: [initiator_certificate])
      ),
      policy: policy
    )
    responder_provider = Edhoc::Credentials::X509Provider.new(
      store: store,
      local: Edhoc::LocalCredential.new(
        private_key: responder_key,
        identification: Edhoc::Credentials::X5Chain.new(certificates: [responder_certificate])
      ),
      policy: policy
    )
    initiator = Edhoc::Session.new(
      role: :initiator, methods: [0], cipher_suites: [0], connection_id: -14,
      credentials: initiator_provider
    )
    responder = Edhoc::Session.new(
      role: :responder, methods: [0], cipher_suites: [0], connection_id: "\x18".b,
      credentials: responder_provider
    )
    handshake(initiator, responder)

    expect(initiator.peer_id).to be == 'responder'
    expect(responder.peer_id).to be == 'initiator'
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects a chain not accepted by the configured store' do
    _root, initiator_key, initiator_certificate, responder_key, responder_certificate = x509_pair
    empty_store = OpenSSL::X509::Store.new
    initiator_provider = Edhoc::Credentials::X509Provider.new(
      store: empty_store,
      local: Edhoc::LocalCredential.new(
        private_key: initiator_key,
        identification: Edhoc::Credentials::X5Chain.new(certificates: [initiator_certificate])
      )
    )
    responder_provider = Edhoc::Credentials::X509Provider.new(
      store: empty_store,
      local: Edhoc::LocalCredential.new(
        private_key: responder_key,
        identification: Edhoc::Credentials::X5Chain.new(certificates: [responder_certificate])
      )
    )
    initiator = Edhoc::Session.new(
      role: :initiator, methods: [0], cipher_suites: [0], connection_id: -14,
      credentials: initiator_provider
    )
    responder = Edhoc::Session.new(
      role: :responder, methods: [0], cipher_suites: [0], connection_id: "\x18".b,
      credentials: responder_provider
    )
    responder.process_message1(initiator.compose_message1)

    expect { initiator.process_message2(responder.compose_message2) }
      .to raise_exception(Edhoc::CredentialsError)
    expect(initiator.state).to be == :aborted
  ensure
    initiator&.close
    responder&.close
  end

  it 'round-trips raw and CBOR KID credentials' do
    keys = credential_keys
    kid_cases.each { |credential_case| assert_credential_round_trip(keys, credential_case) }
  end

  it 'round-trips one-to-three x5chain entries' do
    keys = credential_keys
    initiator_key, responder_key = keys
    initiator_certificate = certificate('initiator', initiator_key)
    responder_certificate = certificate('responder', responder_key)

    x5chain_cases(initiator_certificate, responder_certificate).each do |credential_case|
      assert_credential_round_trip(keys, credential_case)
    end
  end

  it 'round-trips x5t integer and text algorithm forms' do
    keys = credential_keys
    initiator_key, responder_key = keys
    initiator_certificate = certificate('initiator', initiator_key)
    responder_certificate = certificate('responder', responder_key)

    x5t_cases(initiator_certificate, responder_certificate).each do |credential_case|
      assert_credential_round_trip(keys, credential_case)
    end
  end

  it 're-raises the original callback exception and aborts the session' do
    callback_error = RuntimeError.new('callback failed')
    provider_class = Class.new do
      define_method(:initialize) { |error| @error = error }
      def select_local(_context) = raise(@error)
      def authenticate_peer(_context, _received) = nil
    end
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    initiator = Edhoc::Session.new(
      role: :initiator, methods: [0], cipher_suites: [0], connection_id: -14,
      credentials: TestCredentialProvider.new(
        identity: initiator_identity, peer: responder_identity
      )
    )
    responder = Edhoc::Session.new(
      role: :responder, methods: [0], cipher_suites: [0], connection_id: "\x18".b,
      credentials: provider_class.new(callback_error)
    )

    responder.process_message1(initiator.compose_message1)
    caught = nil
    begin
      responder.compose_message2
    rescue RuntimeError => e
      caught = e
    end
    expect(caught.object_id).to be == callback_error.object_id
    expect(responder.state).to be == :aborted
  ensure
    initiator&.close
    responder&.close
  end

  def credential_keys
    [OpenSSL::PKey.generate_key('ED25519'), OpenSSL::PKey.generate_key('ED25519')]
  end

  def kid_cases
    [
      [
        Edhoc::Credentials::KID.new(identifier: 'i', credential: 'initiator'.b, format: :raw),
        Edhoc::Credentials::KID.new(identifier: 'r', credential: 'responder'.b, format: :raw),
        'initiator'.b, 'responder'.b, :kid, :raw
      ],
      [
        Edhoc::Credentials::KID.new(identifier: 'i', credential: "\xa1\x01\x02".b, format: :cbor),
        Edhoc::Credentials::KID.new(identifier: 'r', credential: "\xa1\x01\x03".b, format: :cbor),
        "\xa1\x01\x02".b, "\xa1\x01\x03".b, :kid, :cbor
      ]
    ]
  end

  def assert_credential_round_trip(keys, credential_case)
    initiator_key, responder_key = keys
    initiator_id, responder_id, initiator_cred, responder_cred, kind, format = credential_case
    initiator_provider = CapturingCredentialProvider.new(
      key: initiator_key, identification: initiator_id, peer_key: responder_key,
      peer_credential: responder_cred, peer_format: format || :raw
    )
    responder_provider = CapturingCredentialProvider.new(
      key: responder_key, identification: responder_id, peer_key: initiator_key,
      peer_credential: initiator_cred, peer_format: format || :raw
    )
    initiator = Edhoc::Session.new(
      role: :initiator, methods: [0], cipher_suites: [0], connection_id: -14,
      credentials: initiator_provider
    )
    responder = Edhoc::Session.new(
      role: :responder, methods: [0], cipher_suites: [0], connection_id: "\x18".b,
      credentials: responder_provider
    )
    handshake(initiator, responder)
    expect(initiator_provider.received.kind).to be == kind
    expect(responder_provider.received.kind).to be == kind
  ensure
    initiator&.close
    responder&.close
  end

  def x5chain_cases(initiator_certificate, responder_certificate)
    (1..3).map do |count|
      initiator_chain = [initiator_certificate] * count
      responder_chain = [responder_certificate] * count
      [
        Edhoc::Credentials::X5Chain.new(certificates: initiator_chain),
        Edhoc::Credentials::X5Chain.new(certificates: responder_chain),
        initiator_certificate.to_der, responder_certificate.to_der, :x5chain
      ]
    end
  end

  def x5t_cases(initiator_certificate, responder_certificate)
    [-15, 'SHA256'].map do |algorithm|
      initiator_fingerprint = fingerprint(algorithm, initiator_certificate)
      responder_fingerprint = fingerprint(algorithm, responder_certificate)
      [
        Edhoc::Credentials::X5T.new(
          algorithm: algorithm, fingerprint: initiator_fingerprint,
          certificate: initiator_certificate
        ),
        Edhoc::Credentials::X5T.new(
          algorithm: algorithm, fingerprint: responder_fingerprint,
          certificate: responder_certificate
        ),
        initiator_certificate.to_der, responder_certificate.to_der, :x5t
      ]
    end
  end

  def fingerprint(algorithm, certificate)
    digest = OpenSSL::Digest::SHA256.digest(certificate.to_der)
    algorithm == -15 ? digest.byteslice(0, 8) : digest
  end
end
