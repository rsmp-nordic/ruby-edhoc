module Edhoc
  # A typed RFC 9528 protocol error message.
  class ErrorMessage
    CODES = {
      success: 0,
      unspecified: 1,
      wrong_selected_cipher_suite: 2,
      unknown_credential_referenced: 3
    }.freeze
    CODE_NAMES = CODES.invert.freeze

    attr_reader :code, :text, :cipher_suites

    def initialize(code:, text: nil, cipher_suites: nil)
      @code = normalize_code(code)
      @text = text.nil? ? nil : String(text).dup.freeze
      @cipher_suites = cipher_suites&.map { |suite| Integer(suite) }&.freeze
      validate!
      freeze
    end

    def self.parse(bytes)
      values = Native.error_message_parse(String(bytes).b)
      suites = values[:cipher_suites]&.reverse
      new(code: values.fetch(:code), text: values[:text], cipher_suites: suites)
    end

    def to_bytes
      Native.error_message_compose(
        CODES.fetch(@code), @text, @cipher_suites&.reverse
      )
    end

    private

    def normalize_code(value)
      return CODE_NAMES.fetch(Integer(value)) if value.is_a?(Integer)

      value.to_sym.tap { |name| CODES.fetch(name) }
    rescue KeyError
      raise ArgumentError, "unknown EDHOC protocol error code #{value.inspect}"
    end

    def validate!
      case @code
      when :unspecified
        raise ArgumentError, 'unspecified error requires text' if @text.nil?
      when :wrong_selected_cipher_suite
        unless @cipher_suites && (1..3).cover?(@cipher_suites.length)
          raise ArgumentError, 'wrong-selected-cipher-suite error requires one to three cipher suites'
        end
      end
    end
  end
end
