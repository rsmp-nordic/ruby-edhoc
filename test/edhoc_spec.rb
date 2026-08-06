require_relative 'test_helper'

describe Edhoc::Session do
  include SessionTestHelpers

  it 'completes all method and cipher-suite combinations with matching exporters' do
    [0, 2, 4, 24].product((0..3).to_a).each do |suite, method|
      initiator, responder = sessions(method: method, suites: [suite])
      handshake(initiator, responder, message4: true)

      expect(initiator.state).to be == :persisted
      expect(responder.state).to be == :persisted
      expect(initiator.selected_method).to be == method
      expect(initiator.selected_cipher_suite).to be == suite
      expect(initiator.export(label: 0, length: 32)).to be ==
                                                        responder.export(label: 0, length: 32)
    ensure
      initiator&.close
      responder&.close
    end
  end

  it 'uses the first Ruby suite preference while advertising one to three suites' do
    initiator, responder = sessions(method: 0, suites: [24, 2, 0])
    handshake(initiator, responder)

    expect(initiator.selected_cipher_suite).to be == 24
    expect(responder.selected_cipher_suite).to be == 24
    expect(initiator.diagnostics.cipher_suites).to be == [24, 2, 0]
  ensure
    initiator&.close
    responder&.close
  end

  it 'offers all methods in preference order and selects the first mutual method' do
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    common = { cipher_suites: [0], max_message_size: 65_536 }
    initiator = Edhoc::Session.new(
      **common,
      role: :initiator,
      methods: [3, 2, 1, 0],
      connection_id: -14,
      credentials: TestCredentialProvider.new(
        identity: initiator_identity, peer: responder_identity
      )
    )
    responder = Edhoc::Session.new(
      **common,
      role: :responder,
      methods: [3, 2],
      connection_id: "\x18".b,
      credentials: TestCredentialProvider.new(
        identity: responder_identity, peer: initiator_identity
      )
    )
    handshake(initiator, responder)

    expect(initiator.selected_method).to be == 3
    expect(responder.selected_method).to be == 3
    expect(initiator.methods).to be == [3, 2, 1, 0]
  ensure
    initiator&.close
    responder&.close
  end

  it 'composes a negotiation error, records peer suites, restarts, and retries' do
    initiator, responder = negotiating_sessions(
      method: 0, initiator_suites: [0, 4], responder_suites: [2, 24]
    )
    message1 = initiator.compose_message1
    caught = nil
    begin
      responder.process_message1(message1)
    rescue Edhoc::MessageError => e
      caught = e
    end
    expect(caught).to be_a(Edhoc::MessageError)
    expect(caught.protocol_code).to be == 2
    expect(caught.local_cipher_suites).to be == [2, 24]
    expect(caught.peer_cipher_suites).to be == [0, 4]
    expect(responder.error_message.cipher_suites).to be == [2, 24]

    parsed = initiator.process_error_message(responder.error_message.to_bytes)
    expect(parsed.code).to be == :wrong_selected_cipher_suite
    expect(initiator.error_message.object_id).to be == parsed.object_id
    expect(initiator.diagnostics.peer_cipher_suites).to be == [2, 24]

    initiator.restart!(cipher_suites: [2])
    responder.restart!(cipher_suites: [2])
    handshake(initiator, responder)
    expect(initiator.selected_cipher_suite).to be == 2
  ensure
    initiator&.close
    responder&.close
  end

  it 'exports OSCORE in the correct direction and supports key update' do
    initiator, responder = sessions(method: 2, suites: [2])
    handshake(initiator, responder)
    initiator_context = initiator.export_oscore_context
    responder_context = responder.export_oscore_context

    expect(initiator_context.master_secret).to be == responder_context.master_secret
    expect(initiator_context.master_salt).to be == responder_context.master_salt
    expect(initiator_context.sender_id).to be == responder_context.recipient_id
    expect(initiator_context.recipient_id).to be == responder_context.sender_id
    expect { initiator.export_oscore_context }.to raise_exception(Edhoc::BadStateError)

    initiator.key_update!('next')
    responder.key_update!('next')
    expect(initiator.export_oscore_context.master_secret).to be ==
                                                             responder.export_oscore_context.master_secret
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects invalid preferences and legacy preset arguments' do
    provider = TestCredentialProvider.new(identity: identity('a', 1), peer: identity('b', 2))
    common = { role: :initiator, connection_id: 1, credentials: provider }

    expect { Edhoc::Session.new(**common, methods: [0, 0], cipher_suites: [0]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [4], cipher_suites: [0]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [0], cipher_suites: [0, 2, 4, 24]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Suite0Session.new(**common, methods: [0], private_key: 'legacy') }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [], cipher_suites: [0]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [0], cipher_suites: [0, 0]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [0], cipher_suites: [1]) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Session.new(**common, methods: [0], cipher_suites: [0], max_message_size: 0) }
      .to raise_exception(ArgumentError)
    expect do
      Edhoc::Session.new(**common, role: :client, methods: [0], cipher_suites: [0])
    end.to raise_exception(ArgumentError)
  end

  it 'enforces message-size bounds for composition and processing' do
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    initiator = Edhoc::Session.new(
      role: :initiator, methods: [0], cipher_suites: [0], connection_id: -14,
      credentials: TestCredentialProvider.new(identity: initiator_identity, peer: responder_identity),
      max_message_size: 1
    )
    responder = Edhoc::Session.new(
      role: :responder, methods: [0], cipher_suites: [0], connection_id: "\x18".b,
      credentials: TestCredentialProvider.new(identity: responder_identity, peer: initiator_identity),
      max_message_size: 1
    )

    expect { initiator.compose_message1 }.to raise_exception(Edhoc::CborError)
    expect { responder.process_message1("\x01\x02".b) }.to raise_exception(ArgumentError)
  ensure
    initiator&.close
    responder&.close
  end

  it 'provides both convenience suite presets and rejects attempts to override them' do
    initiator_identity = identity('initiator', 1)
    responder_identity = identity('responder', 2)
    common = {
      role: :initiator, methods: [0], connection_id: -14,
      credentials: TestCredentialProvider.new(identity: initiator_identity, peer: responder_identity)
    }
    suite0 = Edhoc::Suite0Session.new(**common)
    suite4 = Edhoc::Suite4Session.new(**common)

    expect(suite0.cipher_suites).to be == [0]
    expect(suite4.cipher_suites).to be == [4]
    expect { Edhoc::Suite0Session.new(**common, cipher_suites: [2]) }.to raise_exception(ArgumentError)
    expect { Edhoc::Suite4Session.new(**common, cipher_suites: [2]) }.to raise_exception(ArgumentError)
  ensure
    suite0&.close
    suite4&.close
  end

  it 'maps unspecified and credential protocol errors to typed messages' do
    native = Struct.new(:protocol_error_code, :error_text, :local_cipher_suites)
    session = Edhoc::Session.allocate

    session.instance_variable_set(:@native, native.new(1, nil, []))
    unspecified = session.error_message
    expect(unspecified.code).to be == :unspecified
    expect(unspecified.text).to be == 'EDHOC operation failed'

    session.instance_variable_set(:@native, native.new(1, 'peer rejected EAD', []))
    expect(session.error_message.text).to be == 'peer rejected EAD'

    session.instance_variable_set(:@native, native.new(3, nil, []))
    expect(session.error_message.code).to be == :unknown_credential_referenced
  end

  it 'retains callback objects through GC compaction and closes idempotently' do
    initiator, responder = sessions(method: 1, suites: [4])
    GC.start
    GC.compact
    responder.process_message1(initiator.compose_message1)
    GC.compact
    initiator.process_message2(responder.compose_message2)
    GC.compact
    responder.process_message3(initiator.compose_message3)

    expect(initiator.peer_id).to be == 'responder'
    initiator.close
    expect { initiator.close }.not.to raise_exception
    expect(initiator.closed?).to be == true
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects message operations for the wrong role or state' do
    initiator, responder = sessions(method: 0)

    expect { initiator.compose_message2 }.to raise_exception(Edhoc::BadStateError)
    expect { responder.compose_message1 }.to raise_exception(Edhoc::BadStateError)
    initiator.compose_message1
    expect { initiator.compose_message1 }.to raise_exception(Edhoc::BadStateError)
  ensure
    initiator&.close
    responder&.close
  end
end

describe Edhoc::ErrorMessage do
  it 'round-trips every protocol error variant' do
    messages = [
      Edhoc::ErrorMessage.new(code: :success),
      Edhoc::ErrorMessage.new(code: :unspecified, text: 'diagnostic'),
      Edhoc::ErrorMessage.new(code: :wrong_selected_cipher_suite, cipher_suites: [24, 2, 0]),
      Edhoc::ErrorMessage.new(code: :unknown_credential_referenced)
    ]

    messages.each do |message|
      parsed = Edhoc::ErrorMessage.parse(message.to_bytes)
      expect(parsed.code).to be == message.code
      expect(parsed.text).to be == message.text
      expect(parsed.cipher_suites).to be == message.cipher_suites
    end
  end

  it 'rejects malformed CBOR' do
    expect { Edhoc::ErrorMessage.parse("\xff".b) }.to raise_exception(Edhoc::CborError)
  end

  it 'safely parses or rejects a deterministic malformed-input corpus' do
    random = Random.new(20_260_806)
    100.times do
      bytes = random.bytes(random.rand(0..32))
      begin
        result = Edhoc::ErrorMessage.parse(bytes)
        expect(Edhoc::ErrorMessage::CODES.key?(result.code)).to be == true
      rescue Edhoc::NativeError => e
        expect(e.code).to be_a(Symbol)
        expect(e.code_number).to be_a(Integer)
      end
    end
  end
end

describe Edhoc::CoAP do
  it 'prepends and extracts flow and connection IDs' do
    message = "\x01\x02".b
    flow = Edhoc::CoAP.extract_flow(Edhoc::CoAP.prepend_flow(message))
    expect(flow).to be == { forward: true, reverse: false, message: message }

    connected = Edhoc::CoAP.extract_connection_id(
      Edhoc::CoAP.prepend_connection_id(message, -14)
    )
    expect(connected.fetch(:message)).to be == message
    expect(Edhoc::CoAP.connection_id_equal?(connected.fetch(:connection_id), -14)).to be == true
    expect(Edhoc::CoAP.connection_id_equal?('a', 'b')).to be == false
  end
end
