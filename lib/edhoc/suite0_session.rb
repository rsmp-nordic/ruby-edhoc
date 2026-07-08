require 'openssl'

module Edhoc
  # Stateful EDHOC suite 0 handshake session backed by libedhoc.
  class Suite0Session
    OPTION_KEYS = %i[
      role
      private_key
      credential
      peer_public_key
      peer_credential
      peer_kid
      peers
      credential_format
      kid
      connection_id
    ].freeze
    DEFAULT_INITIATOR_CONNECTION_ID = -14
    DEFAULT_RESPONDER_CONNECTION_ID = "\x18".b.freeze

    def initialize(**options)
      validate_options!(options)
      role = options.fetch(:role).to_sym
      options[:connection_id] ||= default_connection_id(role)

      @native = build_native_session(options.merge(role: role))
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
      certificate.subject.to_a.find { |name, _value, _type| name == 'CN' }&.fetch(1)
    rescue OpenSSL::X509::CertificateError
      nil
    end

    def validate_options!(options)
      unknown = options.keys - OPTION_KEYS
      raise ArgumentError, "unknown keywords: #{unknown.join(', ')}" unless unknown.empty?

      %i[role private_key credential].each { |key| options.fetch(key) }
    end

    def build_native_session(options)
      Native::Suite0Session.new(*native_session_arguments(options))
    end

    def native_session_arguments(options)
      common = [
        options.fetch(:role).to_s,
        String(options.fetch(:private_key)).b,
        String(options.fetch(:credential)).b
      ]
      format = credential_format(options)
      common += [format, String(options.fetch(:kid)).b] if format == 'kid_cbor'

      if options[:peers]
        common + [peer_tuples(options.fetch(:peers)), options.fetch(:connection_id)]
      else
        common + single_peer_arguments(options)
      end
    end

    def single_peer_arguments(options)
      arguments = [
        String(options.fetch(:peer_public_key)).b,
        String(options.fetch(:peer_credential)).b
      ]
      arguments << String(options.fetch(:peer_kid)).b if credential_format(options) == 'kid_cbor'
      arguments << options.fetch(:connection_id)
      arguments
    end

    def peer_tuples(peers)
      peers.map do |peer|
        tuple = [
          peer[:id] || peer['id'],
          String(peer.fetch(:public_key) { peer.fetch('public_key') }).b,
          String(peer.fetch(:credential) { peer.fetch('credential') }).b
        ]
        tuple << String(peer.fetch(:kid) { peer.fetch('kid') }).b if credential_format_symbol == :kid_cbor
        tuple
      end
    end

    def credential_format(options)
      @credential_format ||= begin
        format = options.fetch(:credential_format, :x509_chain).to_sym
        unless %i[x509_chain kid_cbor].include?(format)
          raise ArgumentError, 'credential_format must be :x509_chain or :kid_cbor'
        end

        format.to_s
      end
    end

    def credential_format_symbol
      @credential_format.to_sym
    end

    def default_connection_id(role)
      case role
      when :initiator
        DEFAULT_INITIATOR_CONNECTION_ID
      when :responder
        DEFAULT_RESPONDER_CONNECTION_ID
      else
        raise ArgumentError, 'role must be :initiator or :responder'
      end
    end
  end
end
