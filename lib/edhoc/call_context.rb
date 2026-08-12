module Edhoc
  # Describes the protocol operation for a credentials or EAD callback.
  class CallContext
    ROLES = %i[initiator responder].freeze
    AUTHENTICATION_KINDS = %i[signature static_dh].freeze

    attr_reader :role, :method, :cipher_suite, :message, :authentication

    alias suite cipher_suite
    alias authentication_kind authentication

    def initialize(role:, method:, cipher_suite:, message:, authentication: nil)
      @role = role.to_sym
      @method = Integer(method)
      @cipher_suite = Integer(cipher_suite)
      @message = Integer(message)
      @authentication = authentication&.to_sym
      validate!
      freeze
    end

    def self.from_native(values)
      new(
        role: values.fetch(:role), method: values.fetch(:method),
        cipher_suite: values.fetch(:cipher_suite), message: values.fetch(:message),
        authentication: values[:authentication]
      )
    end

    private

    def validate!
      raise ArgumentError, 'invalid callback role' unless ROLES.include?(@role)
      raise ArgumentError, 'method must be between 0 and 3' unless (0..3).cover?(@method)
      raise ArgumentError, 'message must be between 1 and 4' unless (1..4).cover?(@message)
      return if @authentication.nil? || AUTHENTICATION_KINDS.include?(@authentication)

      raise ArgumentError, 'invalid authentication kind'
    end
  end
end
