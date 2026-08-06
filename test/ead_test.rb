require_relative 'test_helper'

class TestEadHandler
  attr_reader :received

  def initialize(critical: false)
    @critical = critical
    @received = []
  end

  def compose(context)
    label = context.message * 10
    label = -label if @critical
    [
      Edhoc::EAD::Token.new(label: label),
      Edhoc::EAD::Token.new(label: label + 1, value: ''.b),
      Edhoc::EAD::Token.new(label: label + 2, value: "message-#{context.message}".b)
    ]
  end

  def process(context, tokens)
    @received << [context.message, tokens]
  end

  def supports?(label) = label.between?(10, 40)
end

describe Edhoc::EAD do
  include SessionTestHelpers

  it 'validates token bounds and the handler contract' do
    expect { Edhoc::EAD::Token.new(label: 2**31) }.to raise_exception(RangeError)
    expect { Edhoc::EAD::Bridge.new(Object.new) }.to raise_exception(ArgumentError)

    handler = Class.new do
      attr_accessor :result

      def compose(_context) = @result
      def process(_context, _tokens) = nil
      def supports?(_label) = true
    end.new
    bridge = Edhoc::EAD::Bridge.new(handler)
    context = {
      role: :initiator, method: 0, cipher_suite: 0,
      message: 1, authentication: nil
    }
    expect(bridge.__native_compose(context)).to be == []
    handler.result = [Object.new]
    expect { bridge.__native_compose(context) }.to raise_exception(TypeError)
  end

  it 'passes the absolute value of supported critical labels to the handler' do
    handler = Class.new do
      attr_reader :supported, :processed

      def compose(_context) = []

      def supports?(label)
        @supported = label
        true
      end

      def process(_context, tokens) = @processed = tokens
    end.new
    bridge = Edhoc::EAD::Bridge.new(handler)
    context = {
      role: :responder, method: 0, cipher_suite: 0,
      message: 1, authentication: nil
    }

    expect(bridge.__native_process(context, [[-42, nil]])).to be_nil
    expect(handler.supported).to be == 42
    expect(handler.processed.first.label_only?).to be == true
  end

  it 'preserves label-only, empty, and valued tokens in messages 1 through 4' do
    initiator_handler = TestEadHandler.new
    responder_handler = TestEadHandler.new
    initiator, responder = sessions(
      method: 0, suites: [0], initiator_ead: initiator_handler,
      responder_ead: responder_handler
    )
    handshake(initiator, responder, message4: true)

    received = initiator_handler.received + responder_handler.received
    expect(received.map(&:first).sort).to be == [1, 2, 3, 4]
    received.each do |entry|
      tokens = entry.last
      expect(tokens[0].label_only?).to be == true
      expect(tokens[1].label_only?).to be == false
      expect(tokens[1].value).to be == ''.b
    end
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects an unsupported critical label and preserves the callback exception' do
    sender = TestEadHandler.new(critical: true)
    receiver_class = Class.new(TestEadHandler) do
      def supports?(_label) = false
    end
    initiator, responder = sessions(
      method: 0, suites: [0], initiator_ead: sender,
      responder_ead: receiver_class.new
    )

    expect { responder.process_message1(initiator.compose_message1) }
      .to raise_exception(Edhoc::EadError)
    expect(responder.state).to be == :aborted
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects more than three composed tokens' do
    handler_class = Class.new(TestEadHandler) do
      def compose(_context)
        4.times.map { |label| Edhoc::EAD::Token.new(label: label + 1) }
      end
    end
    initiator, responder = sessions(method: 0, initiator_ead: handler_class.new)

    expect { initiator.compose_message1 }.to raise_exception(ArgumentError)
    expect(initiator.state).to be == :aborted
  ensure
    initiator&.close
    responder&.close
  end
end
