require_relative "test_helper"

describe Edhoc do
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

    message1 = initiator.compose_message1
    expect(message1.bytesize).to be > 0
    expect(responder.process_message1(message1)).to be == true

    message2 = responder.compose_message2
    expect(message2.bytesize).to be > 0
    expect(initiator.process_message2(message2)).to be == true

    message3 = initiator.compose_message3
    expect(message3.bytesize).to be > 0
    expect(responder.process_message3(message3)).to be == true

    initiator_secret = initiator.export_prk(0, 16)
    responder_secret = responder.export_prk(0, 16)

    expect(initiator_secret.bytesize).to be == 16
    expect(initiator_secret).to be == responder_secret
  end
end
