require_relative "test_helper"

describe Edhoc do
  def suite0_sessions(vector)
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )

    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peer_public_key: vector.fetch(:initiator_public_key),
      peer_credential: vector.fetch(:initiator_credential)
    )

    [initiator, responder]
  end

  def run_suite0_handshake(initiator, responder)
    message1 = initiator.compose_message1
    expect(message1.bytesize).to be > 0
    expect(responder.process_message1(message1)).to be == true

    message2 = responder.compose_message2
    expect(message2.bytesize).to be > 0
    expect(initiator.process_message2(message2)).to be == true

    message3 = initiator.compose_message3
    expect(message3.bytesize).to be > 0
    expect(responder.process_message3(message3)).to be == true
  end

  it "exposes native profile metadata for the secure RSMP candidate" do
    profile = Edhoc::Native.suite0_profile

    expect(profile.fetch(:method)).to be == 0
    expect(profile.fetch(:cipher_suite)).to be == 0
    expect(profile.fetch(:ecdh)).to be == "X25519"
    expect(profile.fetch(:signature)).to be == "Ed25519/EdDSA"
    expect(profile.fetch(:hash)).to be == "SHA-256"
  end

  it "runs a suite 0 initiator/responder handshake" do
    vector = Edhoc::Native.suite0_test_vector
    initiator, responder = suite0_sessions(vector)
    run_suite0_handshake(initiator, responder)

    initiator_secret = initiator.export_prk(0, 16)
    responder_secret = responder.export_prk(0, 16)

    expect(initiator_secret.bytesize).to be == 16
    expect(initiator_secret).to be == responder_secret
  ensure
    initiator&.close
    responder&.close
  end

  it "matches a known peer from a responder peer set" do
    vector = Edhoc::Native.suite0_test_vector
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )
    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peers: [
        {
          id: "other-site",
          public_key: "x" * 32,
          credential: "not the initiator credential"
        },
        {
          id: "site-a",
          public_key: vector.fetch(:initiator_public_key),
          credential: vector.fetch(:initiator_credential)
        }
      ]
    )

    run_suite0_handshake(initiator, responder)

    expect(responder.matched_peer_id).to be == "site-a"
  ensure
    initiator&.close
    responder&.close
  end

  it "rejects unknown peers in a responder peer set" do
    vector = Edhoc::Native.suite0_test_vector
    initiator = Edhoc::Suite0Session.new(
      role: :initiator,
      private_key: vector.fetch(:initiator_private_key),
      credential: vector.fetch(:initiator_credential),
      peer_public_key: vector.fetch(:responder_public_key),
      peer_credential: vector.fetch(:responder_credential)
    )
    responder = Edhoc::Suite0Session.new(
      role: :responder,
      private_key: vector.fetch(:responder_private_key),
      credential: vector.fetch(:responder_credential),
      peers: [
        {
          id: "other-site",
          public_key: "x" * 32,
          credential: "not the initiator credential"
        }
      ]
    )

    responder.process_message1(initiator.compose_message1)
    initiator.process_message2(responder.compose_message2)

    expect do
      responder.process_message3(initiator.compose_message3)
    end.to raise_exception(Edhoc::CredentialsError)
  ensure
    initiator&.close
    responder&.close
  end

  it "releases native key handles across repeated handshakes" do
    vector = Edhoc::Native.suite0_test_vector

    25.times do
      initiator, responder = suite0_sessions(vector)
      run_suite0_handshake(initiator, responder)
    ensure
      initiator&.close
      responder&.close
    end
  end

  it "raises typed Ruby exceptions for native libedhoc failures" do
    vector = Edhoc::Native.suite0_test_vector
    initiator, = suite0_sessions(vector)

    expect(Edhoc::NativeError < Edhoc::Error).to be == true
    expect(Edhoc::BadStateError < Edhoc::NativeError).to be == true

    error = nil
    begin
      initiator.export_prk(0, 16)
    rescue Edhoc::BadStateError => e
      error = e
    end

    expect(error).to be_a(Edhoc::BadStateError)
    expect(error.message).to be(:include?, "bad_state (-104)")
  ensure
    initiator&.close
  end
end
