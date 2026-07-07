module Edhoc
  class Suite0Session
    DEFAULT_INITIATOR_CONNECTION_ID = -14
    DEFAULT_RESPONDER_CONNECTION_ID = "\x18".b.freeze

    def initialize(role:, private_key:, credential:, peer_public_key:, peer_credential:, connection_id: nil)
      role = role.to_sym
      connection_id ||= default_connection_id(role)

      @native = Native::Suite0Session.new(
        role.to_s,
        String(private_key).b,
        String(credential).b,
        String(peer_public_key).b,
        String(peer_credential).b,
        connection_id
      )
    end

    def compose_message1 = @native.compose_message1
    def process_message1(message) = @native.process_message1(String(message).b)
    def compose_message2 = @native.compose_message2
    def process_message2(message) = @native.process_message2(String(message).b)
    def compose_message3 = @native.compose_message3
    def process_message3(message) = @native.process_message3(String(message).b)
    def export_prk(label, length) = @native.export_prk(Integer(label), Integer(length))

    private

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
