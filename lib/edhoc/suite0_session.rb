require "openssl"

module Edhoc
  class Suite0Session
    DEFAULT_INITIATOR_CONNECTION_ID = -14
    DEFAULT_RESPONDER_CONNECTION_ID = "\x18".b.freeze

    def initialize(role:, private_key:, credential:, peer_public_key: nil, peer_credential: nil, peers: nil, connection_id: nil)
      role = role.to_sym
      connection_id ||= default_connection_id(role)

      @native = build_native_session(
        role: role,
        private_key: private_key,
        credential: credential,
        peer_public_key: peer_public_key,
        peer_credential: peer_credential,
        peers: peers,
        connection_id: connection_id
      )
    end

    def compose_message1 = @native.compose_message1
    def process_message1(message) = @native.process_message1(String(message).b)
    def compose_message2 = @native.compose_message2
    def process_message2(message) = @native.process_message2(String(message).b)
    def compose_message3 = @native.compose_message3
    def process_message3(message)
      @native.process_message3(String(message).b)
    rescue CredentialsError => e
      raise CredentialsError, untrusted_credential_message(e)
    end

    def export_prk(label, length) = @native.export_prk(Integer(label), Integer(length))
    def matched_peer_id = @native.matched_peer_id
    def close = @native.close

    private

    def untrusted_credential_message(error)
      id = untrusted_credential_id
      return error.message unless id

      "peer credential #{id} not trusted"
    end

    def untrusted_credential_id
      credential = @native.untrusted_credential
      return unless credential

      certificate = OpenSSL::X509::Certificate.new(credential)
      certificate.subject.to_a.find { |name, _value, _type| name == "CN" }&.fetch(1)
    rescue OpenSSL::X509::CertificateError
      nil
    end

    def build_native_session(role:, private_key:, credential:, peer_public_key:, peer_credential:, peers:, connection_id:)
      if peers
        Native::Suite0Session.new(
          role.to_s,
          String(private_key).b,
          String(credential).b,
          peer_tuples(peers),
          connection_id
        )
      else
        Native::Suite0Session.new(
          role.to_s,
          String(private_key).b,
          String(credential).b,
          String(peer_public_key).b,
          String(peer_credential).b,
          connection_id
        )
      end
    end

    def peer_tuples(peers)
      peers.map do |peer|
        [
          peer[:id] || peer["id"],
          String(peer.fetch(:public_key) { peer.fetch("public_key") }).b,
          String(peer.fetch(:credential) { peer.fetch("credential") }).b
        ]
      end
    end

    def default_connection_id(role)
      case role
      when :initiator
        DEFAULT_INITIATOR_CONNECTION_ID
      when :responder
        DEFAULT_RESPONDER_CONNECTION_ID
      else
        raise ArgumentError, "role must be :initiator or :responder"
      end
    end
  end
end
