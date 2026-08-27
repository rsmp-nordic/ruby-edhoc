require_relative 'test_helper'
require 'objspace'

describe Edhoc::Native do
  include SessionTestHelpers

  def credential_bridge
    Edhoc::Credentials::ProviderBridge.new(
      TestCredentialProvider.new(identity: identity('local', 1), peer: identity('peer', 2))
    )
  end

  def native_session(**options)
    Edhoc::Native::Session.new(
      options.fetch(:role, :initiator), options.fetch(:methods, [0]),
      options.fetch(:cipher_suites, [0]), options.fetch(:connection_id, -14),
      options.fetch(:credentials, credential_bridge), options[:ead],
      options.fetch(:max_message_size, 65_536)
    )
  end

  def with_sessions(method: 0)
    initiator, responder = sessions(method: method)
    yield initiator, responder
  ensure
    initiator&.close
    responder&.close
  end

  def captured_native_error
    yield
    nil
  rescue Edhoc::NativeError => e
    e
  end

  it 'reports its built-in backend and vendored API version' do
    expect(Edhoc::Native.profile).to be == 'built-in-crypto'
    expect(Edhoc::Native.library_version).to be == '2.2.0'
  end

  it 'defensively validates direct native constructor arguments' do
    bridge = credential_bridge
    invalid = [
      [:client, [0], [0], -14, bridge, nil, 65_536],
      [:initiator, [0], [0], -14, bridge, nil, 0],
      [:initiator, [], [0], -14, bridge, nil, 65_536],
      [:initiator, [0, 1, 2, 3, 0], [0], -14, bridge, nil, 65_536],
      [:initiator, [0], [], -14, bridge, nil, 65_536],
      [:initiator, [0], [0, 2, 4, 24], -14, bridge, nil, 65_536],
      [:initiator, [0], [1], -14, bridge, nil, 65_536],
      [:initiator, [0], [0], -25, bridge, nil, 65_536],
      [:initiator, [0], [0], 24, bridge, nil, 65_536],
      [:initiator, [0], [0], '12345678', bridge, nil, 65_536]
    ]

    invalid.each do |arguments|
      expect { Edhoc::Native::Session.new(*arguments) }.to raise_exception(ArgumentError)
    end
  end

  it 'exposes new and closed native diagnostic states safely' do
    session = native_session
    expect(session.state).to be == :new
    expect(session.selected_method).to be_nil
    expect(session.selected_cipher_suite).to be_nil
    expect(session.protocol_error_code).to be_nil
    expect(session.local_cipher_suites).to be == [0]
    expect(session.error_text).to be_nil
    expect(session.closed?).to be == false
    expect(ObjectSpace.memsize_of(session).positive?).to be == true

    diagnostics = session.diagnostics
    expect(diagnostics.fetch(:selected_method)).to be_nil
    expect(diagnostics.fetch(:selected_cipher_suite)).to be_nil
    expect(diagnostics.fetch(:last_operation)).to be_nil
    expect(diagnostics.fetch(:native_error_code)).to be_nil
    session.close
    expect(session.state).to be == :closed
    expect(session.closed?).to be == true
    expect(session.diagnostics.fetch(:closed)).to be == true
    expect { session.selected_method }.to raise_exception(Edhoc::BadStateError)
  ensure
    session&.close
  end

  it 'rejects malformed message 1 selection encodings without reading past input' do
    malformed = [
      ''.b,
      "\x00".b,
      "\x00\x18".b,
      "\x00\x40".b,
      "\x00\x81\x00".b,
      "\x00\x84\x00\x00\x00\x00".b,
      "\x00\x82\x00".b,
      "\x00\x20".b
    ]

    malformed.each do |message|
      session = native_session(role: :responder, connection_id: "\x18".b)
      expect { session.process_message1(message) }.to raise_exception(Edhoc::NativeError)
      expect(session.state).to be == :aborted
      diagnostics = session.diagnostics
      expect(diagnostics.fetch(:native_error_code)).to be_a(Integer)
      expect([nil, 1].include?(diagnostics.fetch(:protocol_error_code))).to be == true
    ensure
      session&.close
    end
  end

  it 'maps structurally short and cryptographically corrupted messages to typed errors' do
    with_sessions do |initiator, _responder|
      initiator.compose_message1
      error = captured_native_error { initiator.process_message2("\x40".b) }
      expect(error).to be_a(Edhoc::MessageError)
      expect(error.code).to be == :message_2_process_failure
    end

    with_sessions do |initiator, _responder|
      initiator.compose_message1
      short_message2 = "\x58\x21".b + ("\0" * 33)
      error = captured_native_error { initiator.process_message2(short_message2) }
      expect(error).to be_a(Edhoc::KeyExchangeError)
      expect(error.code).to be == :ephemeral_key_exchange_failure
    end

    with_sessions do |initiator, responder|
      responder.process_message1(initiator.compose_message1)
      message2 = responder.compose_message2.dup
      message2.setbyte(-1, message2.getbyte(-1) ^ 1)
      error = captured_native_error { initiator.process_message2(message2) }
      expect(error).to be_a(Edhoc::CryptoError)
      # rubocop:disable Naming/VariableNumber
      expect(error.code).to be == :invalid_sign_or_mac_2
      # rubocop:enable Naming/VariableNumber
    end

    with_sessions do |initiator, responder|
      responder.process_message1(initiator.compose_message1)
      initiator.process_message2(responder.compose_message2)
      error = captured_native_error { responder.process_message3("\x40".b) }
      expect(error).to be_a(Edhoc::MessageError)
      expect(error.code).to be == :message_3_process_failure
    end

    with_sessions do |initiator, responder|
      handshake(initiator, responder)
      error = captured_native_error { initiator.process_message4("\x40".b) }
      expect(error).to be_a(Edhoc::MessageError)
      expect(error.code).to be == :message_4_process_failure
    end

    with_sessions do |initiator, responder|
      handshake(initiator, responder)
      message4 = responder.compose_message4.dup
      message4.setbyte(-1, message4.getbyte(-1) ^ 1)
      error = captured_native_error { initiator.process_message4(message4) }
      expect(error).to be_a(Edhoc::CryptoError)
      expect(error.code).to be == :crypto_failure
    end
  end

  it 'rejects invalid exporter and OSCORE output lengths' do
    initiator, responder = sessions(method: 0)
    handshake(initiator, responder)

    expect { initiator.export(label: 0, length: 0) }.to raise_exception(ArgumentError)
    expect { initiator.export(label: 0, length: 1_048_577) }.to raise_exception(ArgumentError)
    expect do
      initiator.export_oscore_context(master_secret_length: 0)
    end.to raise_exception(ArgumentError)
    expect do
      initiator.export_oscore_context(master_salt_length: 1_048_577)
    end.to raise_exception(ArgumentError)
  ensure
    initiator&.close
    responder&.close
  end

  it 'rejects oversized EAD output even when bypassing the Ruby bridge' do
    ead = Object.new
    ead.define_singleton_method(:__native_compose) do |_context|
      4.times.map { |index| [index + 1, nil] }
    end
    ead.define_singleton_method(:__native_process) { |_context, _tokens| nil }
    session = native_session(ead: ead)

    expect { session.compose_message1 }.to raise_exception(Edhoc::EadError)
    expect(session.state).to be == :aborted
  ensure
    session&.close
  end

  it 'rejects malformed local credential hashes at the native boundary' do
    initiator, = sessions(method: 0)
    message1 = initiator.compose_message1
    invalid_results = [
      {
        private_key: "\1" * 64, kind: :x5chain, certificates: []
      },
      {
        private_key: "\1" * 64, kind: :unknown
      },
      {
        private_key: 'short', kind: :kid, identifier: 'id',
        credential: 'credential', format: :raw
      }
    ]

    invalid_results.each do |result|
      credentials = Object.new
      credentials.define_singleton_method(:__native_select_local) { |_context| result }
      credentials.define_singleton_method(:__native_authenticate_peer) { |_context, _received| nil }
      responder = native_session(
        role: :responder, connection_id: "\x18".b, credentials: credentials
      )
      responder.process_message1(message1)
      expect { responder.compose_message2 }.to raise_exception(Edhoc::NativeError)
      expect(responder.state).to be == :aborted
    ensure
      responder&.close
    end
  ensure
    initiator&.close
  end

  it 'validates error-message suite counts below the Ruby value layer' do
    expect do
      Edhoc::Native.error_message_compose(2, nil, [])
    end.to raise_exception(ArgumentError)
    expect do
      Edhoc::Native.error_message_compose(2, nil, [0, 2, 4, 24])
    end.to raise_exception(ArgumentError)
  end
end

describe Edhoc::CoAP do
  it 'recognizes reverse and absent flow indicators' do
    expect(Edhoc::CoAP.extract_flow(''.b)).to be == {
      forward: false, reverse: true, message: ''.b
    }
    expect(Edhoc::CoAP.extract_flow('message'.b)).to be == {
      forward: false, reverse: false, message: 'message'.b
    }
  end

  it 'round-trips every connection-ID representation and rejects invalid IDs' do
    message = 'message'.b
    [-24, -1, 0, 23, ''.b, '1234567'.b].each do |connection_id|
      payload = Edhoc::CoAP.prepend_connection_id(message, connection_id)
      extracted = Edhoc::CoAP.extract_connection_id(payload)
      expect(extracted.fetch(:message)).to be == message
      expect(Edhoc::CoAP.connection_id_equal?(extracted.fetch(:connection_id), connection_id)).to be == true
    end

    [-25, 24, '12345678'.b].each do |connection_id|
      expect { Edhoc::CoAP.prepend_connection_id(message, connection_id) }
        .to raise_exception(ArgumentError)
    end
    expect { Edhoc::CoAP.extract_connection_id(''.b) }
      .to raise_exception(Edhoc::InvalidArgumentError)
    expect { Edhoc::CoAP.extract_connection_id("\xff".b) }
      .to raise_exception(Edhoc::CborError)
    oversized = "\x48".b + '12345678'.b
    expect { Edhoc::CoAP.extract_connection_id(oversized) }
      .to raise_exception(Edhoc::BufferTooSmallError)
  end
end
