module Edhoc
  # A generic initiator or responder EDHOC protocol session.
  class Session
    ROLES = %i[initiator responder].freeze
    METHODS = (0..3)
    CIPHER_SUITES = [0, 2, 4, 24].freeze
    DEFAULT_MAX_MESSAGE_SIZE = 65_536

    Diagnostics = Struct.new(
      :state, :role, :configured_methods, :cipher_suites, :selected_method,
      :selected_cipher_suite, :local_cipher_suites, :peer_cipher_suites,
      :last_operation, :native_error_code, :protocol_error_code, :peer_id,
      :closed, keyword_init: true
    )

    attr_reader :role, :methods, :cipher_suites, :connection_id,
                :max_message_size

    # rubocop:disable-next Metrics/ParameterLists
    def initialize(role:, methods:, cipher_suites:, connection_id:, credentials:, ead: nil,
                   max_message_size: DEFAULT_MAX_MESSAGE_SIZE)
      @role = normalize_role(role)
      @methods = normalize_unique_list(methods, METHODS, 1..4, 'methods')
      @cipher_suites = normalize_unique_list(cipher_suites, CIPHER_SUITES, 1..3, 'cipher_suites')
      @connection_id = connection_id
      @max_message_size = Integer(max_message_size)
      raise ArgumentError, 'max_message_size must be positive' unless @max_message_size.positive?

      @credentials = Credentials::ProviderBridge.new(credentials)
      @ead = ead && EAD::Bridge.new(ead)
      build_native!
    end

    def compose_message1 = @native.compose_message1
    def process_message1(message) = @native.process_message1(binary(message))
    def compose_message2 = @native.compose_message2
    def process_message2(message) = @native.process_message2(binary(message))
    def compose_message3 = @native.compose_message3
    def process_message3(message) = @native.process_message3(binary(message))
    def compose_message4 = @native.compose_message4
    def process_message4(message) = @native.process_message4(binary(message))

    def export(label:, length:, context: ''.b)
      @native.export(Integer(label), binary(context), Integer(length))
    end

    def key_update!(context)
      @native.key_update(binary(context))
      self
    end

    def export_oscore_context(master_secret_length: 16, master_salt_length: 8)
      values = @native.export_oscore_context(Integer(master_secret_length), Integer(master_salt_length))
      OscoreContext.new(**values)
    end

    def restart!(cipher_suites: @cipher_suites)
      replacement = normalize_unique_list(cipher_suites, CIPHER_SUITES, 1..3, 'cipher_suites')
      @native.close
      @cipher_suites = replacement
      @peer_error_message = nil
      build_native!
      self
    end

    def process_error_message(bytes)
      @peer_error_message = ErrorMessage.parse(bytes)
    end

    def error_message
      return @peer_error_message if @peer_error_message

      code = @native.protocol_error_code
      return if code.nil?

      name = ErrorMessage::CODE_NAMES.fetch(code)
      if name == :wrong_selected_cipher_suite
        ErrorMessage.new(code: name, cipher_suites: @native.local_cipher_suites.reverse)
      elsif name == :unspecified
        ErrorMessage.new(code: name, text: @native.error_text || 'EDHOC operation failed')
      else
        ErrorMessage.new(code: name)
      end
    end

    def state = @native.state
    def selected_method = @native.selected_method
    def selected_cipher_suite = @native.selected_cipher_suite
    def peer_id = @native.peer_id
    def closed? = @native.closed?
    def close = @native.close

    # rubocop:disable-next Metrics/AbcSize
    def diagnostics
      values = @native.diagnostics
      peer_suites = @peer_error_message&.cipher_suites || values.fetch(:peer_cipher_suites).reverse
      Diagnostics.new(
        state: values.fetch(:state), role: @role, configured_methods: @methods.dup.freeze,
        cipher_suites: @cipher_suites.dup.freeze,
        selected_method: values[:selected_method], selected_cipher_suite: values[:selected_cipher_suite],
        local_cipher_suites: values.fetch(:local_cipher_suites).reverse.freeze,
        peer_cipher_suites: peer_suites.dup.freeze,
        last_operation: values[:last_operation], native_error_code: values[:native_error_code],
        protocol_error_code: values[:protocol_error_code], peer_id: values[:peer_id],
        closed: values.fetch(:closed)
      ).freeze
    end

    private

    def build_native!
      @native = Native::Session.new(
        @role, @methods, @cipher_suites, @connection_id,
        @credentials, @ead, @max_message_size
      )
    end

    def normalize_role(value)
      role = value.to_sym
      raise ArgumentError, 'role must be :initiator or :responder' unless ROLES.include?(role)

      role
    end

    def normalize_unique_list(values, allowed, count, name)
      list = Array(values).map { |value| Integer(value) }
      raise ArgumentError, "#{name} must contain #{count.begin} to #{count.end} values" unless count.cover?(list.length)
      raise ArgumentError, "#{name} must be unique" unless list.uniq.length == list.length

      invalid = list - allowed.to_a
      raise ArgumentError, "unsupported #{name}: #{invalid.join(', ')}" unless invalid.empty?

      list.freeze
    end

    def binary(value) = String(value).b
  end
end
