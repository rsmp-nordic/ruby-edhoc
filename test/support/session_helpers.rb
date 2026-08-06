require 'openssl'

class TestCredentialProvider
  def initialize(identity:, peer:)
    @identity = identity
    @peer = peer
  end

  def select_local(context)
    material = @identity.fetch(context.cipher_suite).fetch(context.authentication)
    Edhoc::LocalCredential.new(
      private_key: material.fetch(:private),
      identification: Edhoc::Credentials::KID.new(
        identifier: @identity.fetch(:id),
        credential: credential(@identity.fetch(:id))
      )
    )
  end

  def authenticate_peer(context, received)
    return unless received.identifier == @peer.fetch(:id)

    material = @peer.fetch(context.cipher_suite).fetch(context.authentication)
    Edhoc::TrustedCredential.new(
      credential: credential(received.identifier), public_key: material.fetch(:public),
      peer_id: received.identifier
    )
  end

  private

  def credential(identifier) = "credential:#{identifier}".b
end

module SessionTestHelpers
  ED25519_PREFIX = ['302e020100300506032b657004220420'].pack('H*').freeze
  X25519_PREFIX = ['302e020100300506032b656e04220420'].pack('H*').freeze

  def identity(id, offset)
    ed_seed = [offset].pack('C') * 32
    ed_key = OpenSSL::PKey.read(ED25519_PREFIX + ed_seed)
    x_seed = [offset + 16].pack('C') * 32
    x_key = OpenSSL::PKey.read(X25519_PREFIX + x_seed)
    p256 = ec_material('prime256v1', 32, offset + 32)
    p384 = ec_material('secp384r1', 48, offset + 48)
    {
      id: id.b,
      0 => curve25519_material(ed_seed, ed_key, x_seed, x_key),
      2 => { signature: p256, static_dh: p256.merge(public: p256.fetch(:x)) },
      4 => curve25519_material(ed_seed, ed_key, x_seed, x_key),
      24 => { signature: p384, static_dh: p384.merge(public: p384.fetch(:x)) }
    }
  end

  def sessions(method:, suites: [0], initiator_ead: nil, responder_ead: nil)
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    initiator = build_session(role: :initiator, method: method, suites: suites, connection_id: -14,
                              identity: initiator_identity, peer: responder_identity, ead: initiator_ead)
    responder = build_session(role: :responder, method: method, suites: suites, connection_id: "\x18".b,
                              identity: responder_identity, peer: initiator_identity, ead: responder_ead)
    [initiator, responder]
  end

  def negotiating_sessions(method:, initiator_suites:, responder_suites:)
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    initiator = build_session(role: :initiator, method: method, suites: initiator_suites,
                              connection_id: -14, identity: initiator_identity,
                              peer: responder_identity, ead: nil)
    responder = build_session(role: :responder, method: method, suites: responder_suites,
                              connection_id: "\x18".b, identity: responder_identity,
                              peer: initiator_identity, ead: nil)
    [initiator, responder]
  end

  def handshake(initiator, responder, message4: false)
    responder.process_message1(initiator.compose_message1)
    initiator.process_message2(responder.compose_message2)
    responder.process_message3(initiator.compose_message3)
    initiator.process_message4(responder.compose_message4) if message4
  end

  private

  def curve25519_material(ed_seed, ed_key, x_seed, x_key)
    {
      signature: { private: ed_seed, public: ed_key.raw_public_key },
      static_dh: { private: x_seed, public: x_key.raw_public_key }
    }
  end

  def ec_material(curve, length, scalar)
    private_key = scalar.to_s(2).rjust(length, "\0")
    group = OpenSSL::PKey::EC::Group.new(curve)
    point = group.generator.mul(OpenSSL::BN.new(private_key, 2))
    public_key = point.to_octet_string(:uncompressed)
    { private: private_key, public: public_key, x: public_key.byteslice(1, length) }
  end

  def build_session(options)
    Edhoc::Session.new(
      role: options.fetch(:role), methods: [options.fetch(:method)],
      cipher_suites: options.fetch(:suites), connection_id: options.fetch(:connection_id),
      credentials: TestCredentialProvider.new(
        identity: options.fetch(:identity), peer: options.fetch(:peer)
      ),
      ead: options.fetch(:ead)
    )
  end
end
