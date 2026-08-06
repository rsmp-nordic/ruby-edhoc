require_relative 'test_helper'

describe Edhoc::CallContext do
  it 'normalizes aliases and rejects invalid callback metadata' do
    context = Edhoc::CallContext.new(
      role: 'initiator', method: '3', cipher_suite: '24',
      message: '4', authentication: 'static_dh'
    )
    expect(context.role).to be == :initiator
    expect(context.suite).to be == 24
    expect(context.authentication_kind).to be == :static_dh
    expect(context.frozen?).to be == true

    expect do
      Edhoc::CallContext.new(role: :client, method: 0, cipher_suite: 0, message: 1)
    end.to raise_exception(ArgumentError)
    expect do
      Edhoc::CallContext.new(role: :initiator, method: 4, cipher_suite: 0, message: 1)
    end.to raise_exception(ArgumentError)
    expect do
      Edhoc::CallContext.new(role: :initiator, method: 0, cipher_suite: 0, message: 0)
    end.to raise_exception(ArgumentError)
    expect do
      Edhoc::CallContext.new(
        role: :initiator, method: 0, cipher_suite: 0,
        message: 1, authentication: :password
      )
    end.to raise_exception(ArgumentError)
  end
end

describe Edhoc::OscoreContext do
  it 'destroys secret material while preserving the non-secret identifiers' do
    master_secret = 'master secret'.b
    master_salt = 'master salt'.b
    context = Edhoc::OscoreContext.new(
      master_secret: master_secret, master_salt: master_salt,
      sender_id: 'sender'.b, recipient_id: 'recipient'.b
    )

    expect(context.destroy!.object_id).to be == context.object_id
    expect(master_secret).to be == ''.b
    expect(master_salt).to be == ''.b
    expect(context.sender_id).to be == 'sender'.b
    expect(context.recipient_id).to be == 'recipient'.b
  end
end

describe Edhoc::ErrorMessage do
  it 'validates numeric codes and required error information' do
    expect(Edhoc::ErrorMessage.new(code: 3).code).to be == :unknown_credential_referenced
    expect { Edhoc::ErrorMessage.new(code: 99) }.to raise_exception(ArgumentError)
    expect { Edhoc::ErrorMessage.new(code: :not_an_edhoc_error) }.to raise_exception(ArgumentError)
    expect { Edhoc::ErrorMessage.new(code: :unspecified) }.to raise_exception(ArgumentError)
    expect do
      Edhoc::ErrorMessage.new(code: :wrong_selected_cipher_suite, cipher_suites: [])
    end.to raise_exception(ArgumentError)
    expect do
      Edhoc::ErrorMessage.new(code: :wrong_selected_cipher_suite, cipher_suites: [0, 2, 4, 24])
    end.to raise_exception(ArgumentError)
  end
end

describe Edhoc::NativeError do
  it 'returns diagnostic suite lists in Ruby preference order, including absent lists' do
    error = Edhoc::NativeError.new('failure')
    expect(error.local_cipher_suites).to be_nil
    expect(error.peer_cipher_suites).to be_nil

    error.instance_variable_set(:@local_cipher_suites, [0, 2, 24])
    error.instance_variable_set(:@peer_cipher_suites, [4, 0])
    expect(error.local_cipher_suites).to be == [24, 2, 0]
    expect(error.peer_cipher_suites).to be == [0, 4]
  end
end
