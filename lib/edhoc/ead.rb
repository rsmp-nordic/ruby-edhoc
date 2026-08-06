module Edhoc
  module EAD
    # An EAD label plus an optional byte-string value.
    class Token
      attr_reader :label, :value

      def initialize(label:, value: nil)
        @label = Integer(label)
        raise RangeError, 'EAD label must fit int32' unless (-(2**31)...(2**31)).cover?(@label)

        @value = value.nil? ? nil : String(value).b.freeze
        freeze
      end

      def label_only? = @value.nil?
    end

    # Internal type-checking adapter between handlers and the native callbacks.
    class Bridge
      def initialize(handler)
        unless handler.respond_to?(:compose) && handler.respond_to?(:process) && handler.respond_to?(:supports?)
          raise ArgumentError, 'ead must implement compose, process, and supports?'
        end

        @handler = handler
      end

      def __native_compose(values)
        tokens = Array(@handler.compose(CallContext.from_native(values)))
        raise ArgumentError, 'EAD compose may return at most three tokens' if tokens.length > 3

        tokens.map do |token|
          raise TypeError, 'EAD compose must return EAD::Token values' unless token.is_a?(Token)

          [token.label, token.value]
        end
      end

      def __native_process(values, encoded_tokens)
        tokens = encoded_tokens.map { |label, value| Token.new(label: label, value: value) }
        unsupported = tokens.find { |token| token.label.negative? && !@handler.supports?(token.label.abs) }
        raise EadError, "unsupported critical EAD label #{unsupported.label}" if unsupported

        @handler.process(CallContext.from_native(values), tokens)
        nil
      end
    end
  end
end
