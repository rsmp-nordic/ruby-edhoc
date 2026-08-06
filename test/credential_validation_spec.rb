require_relative 'test_helper'

describe Edhoc::Credentials do
  include CertificateTestHelpers

  def callback_context(authentication: :signature, cipher_suite: 0)
    Edhoc::CallContext.new(
      role: :initiator, method: 0, cipher_suite: cipher_suite,
      message: 2, authentication: authentication
    )
  end

  def native_context(authentication: :signature, cipher_suite: 0)
    {
      role: :initiator, method: 0, cipher_suite: cipher_suite,
      message: 2, authentication: authentication
    }
  end

  it 'validates and normalizes credential value objects' do
    key = OpenSSL::PKey.generate_key('ED25519')
    cert = certificate('leaf', key)
    der = cert.to_der

    kid = Edhoc::Credentials::KID.new(identifier: 'kid', credential: 'cred')
    expect(kid.identifier.encoding).to be == Encoding::BINARY
    expect(kid.frozen?).to be == true
    expect { Edhoc::Credentials::KID.new(identifier: 'x' * 33, credential: 'cred') }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KID.new(identifier: 'kid', credential: 'cred', format: :pem) }
      .to raise_exception(ArgumentError)

    expect(Edhoc::Credentials::X5Chain.new(certificates: cert).certificates).to be == [der]
    expect { Edhoc::Credentials::X5Chain.new(certificates: []) }.to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::X5Chain.new(certificates: [cert] * 4) }.to raise_exception(ArgumentError)

    named = Edhoc::Credentials::X5T.new(
      algorithm: 'SHA256', fingerprint: 'fingerprint', certificate: cert.to_pem
    )
    expect(named.algorithm).to be == 'SHA256'
    expect(named.certificate).to be == der
    expect { Edhoc::Credentials::X5T.new(algorithm: 'x' * 33, fingerprint: '', certificate: cert) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::X5T.new(algorithm: 2**31, fingerprint: '', certificate: cert) }
      .to raise_exception(RangeError)
    expect { Edhoc::Credentials::X5T.new(algorithm: -16, fingerprint: 'x' * 65, certificate: cert) }
      .to raise_exception(ArgumentError)

    expect { Edhoc::LocalCredential.new(private_key: key, identification: Object.new) }
      .to raise_exception(ArgumentError)
    expect do
      Edhoc::TrustedCredential.new(credential: der, public_key: key, format: :pem)
    end.to raise_exception(ArgumentError)
    expect(Edhoc::Credentials::Certificate.der(cert.to_pem)).to be == der
    expect(Edhoc::Credentials::Certificate.parse(cert).object_id).to be == cert.object_id
    expect { Edhoc::Credentials::Certificate.der('not a certificate') }
      .to raise_exception(ArgumentError)
  end

  it 'normalizes every received credential field to immutable binary data' do
    received = Edhoc::ReceivedCredential.new(
      kind: 'x5t', identifier: 'id', credential: 'cred', format: 'cbor',
      certificates: %w[one two], algorithm: -16, fingerprint: 'hash'
    )

    expect(received.kind).to be == :x5t
    expect(received.format).to be == :cbor
    expect(received.identifier.encoding).to be == Encoding::BINARY
    expect(received.certificates.map(&:encoding)).to be == [Encoding::BINARY, Encoding::BINARY]
    expect(received.certificates.frozen?).to be == true
    expect(received.fingerprint.frozen?).to be == true
  end

  it 'accepts OpenSSL and raw key forms for every supported curve' do
    ed25519 = OpenSSL::PKey.generate_key('ED25519')
    x25519 = OpenSSL::PKey.generate_key('X25519')
    p256 = OpenSSL::PKey::EC.generate('prime256v1')
    p384 = OpenSSL::PKey::EC.generate('secp384r1')
    signature = callback_context
    static_dh = callback_context(authentication: :static_dh)

    ed_private = Edhoc::Credentials::KeyMaterial.private_bytes(ed25519, signature)
    expect(ed_private).to be == ed25519.raw_private_key + ed25519.raw_public_key
    expect(Edhoc::Credentials::KeyMaterial.private_bytes(ed_private, signature)).to be == ed_private
    expect(Edhoc::Credentials::KeyMaterial.public_bytes(ed25519, signature)).to be == ed25519.raw_public_key
    expect(Edhoc::Credentials::KeyMaterial.private_bytes(x25519, static_dh)).to be == x25519.raw_private_key
    expect(Edhoc::Credentials::KeyMaterial.public_bytes(x25519, static_dh)).to be == x25519.raw_public_key

    [[p256, 2, 32, 65], [p384, 24, 48, 97]].each do |key, suite, scalar_length, public_length|
      signature_context = callback_context(cipher_suite: suite)
      static_context = callback_context(authentication: :static_dh, cipher_suite: suite)
      expect(Edhoc::Credentials::KeyMaterial.private_bytes(key, signature_context).bytesize)
        .to be == scalar_length
      expect(Edhoc::Credentials::KeyMaterial.public_bytes(key, signature_context).bytesize)
        .to be == public_length
      expect(Edhoc::Credentials::KeyMaterial.public_bytes(key, static_context).bytesize)
        .to be == scalar_length

      compressed = key.public_key.to_octet_string(:compressed)
      expect(Edhoc::Credentials::KeyMaterial.public_bytes(compressed, static_context))
        .to be == compressed.byteslice(1, scalar_length)
    end
  end

  it 'rejects inconsistent, incorrectly shaped, and incompatible keys' do
    ed25519 = OpenSSL::PKey.generate_key('ED25519')
    x25519 = OpenSSL::PKey.generate_key('X25519')
    p256 = OpenSSL::PKey::EC.generate('prime256v1')
    p384 = OpenSSL::PKey::EC.generate('secp384r1')
    signature = callback_context
    static_dh = callback_context(authentication: :static_dh)
    inconsistent = ed25519.raw_private_key + ("\0" * 32)

    expect { Edhoc::Credentials::KeyMaterial.private_bytes('short', signature) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.private_bytes(inconsistent, signature) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.private_bytes(ed25519, static_dh) }
      .to raise_exception(ArgumentError)
    key_without_oid = Object.new
    key_without_oid.define_singleton_method(:raw_private_key) { "\0" * 32 }
    expect { Edhoc::Credentials::KeyMaterial.private_bytes(key_without_oid, static_dh) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.public_bytes(x25519, signature) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.private_bytes(p384, callback_context(cipher_suite: 2)) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.public_bytes(p256, callback_context(cipher_suite: 24)) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.public_bytes('short', signature) }
      .to raise_exception(ArgumentError)
    expect { Edhoc::Credentials::KeyMaterial.private_bytes('x' * 32, callback_context(cipher_suite: 99)) }
      .to raise_exception(ArgumentError)

    public_only = OpenSSL::PKey.read(p256.public_to_der)
    expect do
      Edhoc::Credentials::KeyMaterial.private_bytes(public_only, callback_context(cipher_suite: 2))
    end.to raise_exception(ArgumentError)
  end

  it 'validates provider callback contracts at the native boundary' do
    expect { Edhoc::Credentials::ProviderBridge.new(Object.new) }.to raise_exception(ArgumentError)

    provider_class = Class.new do
      attr_accessor :local_result, :peer_result

      def select_local(_context) = @local_result
      def authenticate_peer(_context, _received) = @peer_result
    end
    provider = provider_class.new
    bridge = Edhoc::Credentials::ProviderBridge.new(provider)
    received = { kind: :kid, identifier: 'peer', credential: 'credential', format: :raw }

    expect { bridge.__native_select_local(native_context) }.to raise_exception(Edhoc::CredentialsError)
    provider.local_result = 'invalid'
    expect { bridge.__native_select_local(native_context) }.to raise_exception(TypeError)

    provider.local_result = Edhoc::LocalCredential.new(
      private_key: "\1" * 32,
      identification: Edhoc::Credentials::KID.new(identifier: 'local', credential: 'credential')
    )
    selected = bridge.__native_select_local(native_context)
    expect(selected.fetch(:kind)).to be == :kid
    expect(selected.fetch(:private_key).bytesize).to be == 64

    expect(bridge.__native_authenticate_peer(native_context, received)).to be_nil
    provider.peer_result = 'invalid'
    expect { bridge.__native_authenticate_peer(native_context, received) }.to raise_exception(TypeError)
    provider.peer_result = Edhoc::TrustedCredential.new(
      credential: 'credential', public_key: "\2" * 32, format: :cbor, peer_id: 'peer-id'
    )
    trusted = bridge.__native_authenticate_peer(native_context, received)
    expect(trusted).to be == {
      credential: 'credential'.b, format: :cbor,
      public_key: "\2" * 32, peer_id: 'peer-id'
    }
  end

  it 'supports callable and authentication-keyed local X.509 selectors' do
    key = OpenSSL::PKey.generate_key('ED25519')
    credential = Edhoc::LocalCredential.new(
      private_key: key,
      identification: Edhoc::Credentials::X5Chain.new(certificates: [certificate('local', key)])
    )
    store = OpenSSL::X509::Store.new
    signature = callback_context
    static_dh = callback_context(authentication: :static_dh)

    callable = Edhoc::Credentials::X509Provider.new(
      store: store, local: ->(context) { credential if context.authentication == :signature }
    )
    expect(callable.select_local(signature).object_id).to be == credential.object_id

    keyed = Edhoc::Credentials::X509Provider.new(
      store: store, local: { signature: credential, 'static_dh' => credential }
    )
    expect(keyed.select_local(signature).object_id).to be == credential.object_id
    expect(keyed.select_local(static_dh).object_id).to be == credential.object_id
    expect do
      Edhoc::Credentials::X509Provider.new(store: store, local: {}).select_local(signature)
    end.to raise_exception(TypeError)
    expect do
      Edhoc::Credentials::X509Provider.new(store: Object.new, local: credential)
    end.to raise_exception(ArgumentError)
  end

  it 'resolves and verifies x5t credentials, fingerprints, usage, validity, and policy' do
    root_key = OpenSSL::PKey.generate_key('ED25519')
    root = certificate('root', root_key, ca: true)
    leaf_key = OpenSSL::PKey.generate_key('ED25519')
    leaf = certificate('leaf', leaf_key, issuer: root, issuer_key: root_key)
    local = Edhoc::LocalCredential.new(
      private_key: leaf_key,
      identification: Edhoc::Credentials::X5Chain.new(certificates: [leaf])
    )
    context = callback_context
    algorithms = {
      -15 => ['SHA256', 8], -16 => ['SHA256', nil],
      -43 => ['SHA384', nil], -44 => ['SHA512', nil], 'SHA256' => ['SHA256', nil]
    }

    algorithms.each do |algorithm, (digest_name, length)|
      fingerprint = OpenSSL::Digest.new(digest_name).digest(leaf.to_der)
      fingerprint = fingerprint.byteslice(0, length) if length
      received = Edhoc::ReceivedCredential.new(
        kind: :x5t, algorithm: algorithm, fingerprint: fingerprint
      )
      provider = Edhoc::Credentials::X509Provider.new(
        store: certificate_store(root), local: local,
        resolver: ->(_context, _received) { [leaf] }, policy: ->(*) { true }
      )
      expect(provider.authenticate_peer(context, received).peer_id).to be_nil
    end

    rejected = Edhoc::Credentials::X509Provider.new(
      store: certificate_store(root), local: local,
      resolver: ->(*) { [leaf] }, policy: ->(*) { false }
    )
    mismatched = Edhoc::ReceivedCredential.new(
      kind: :x5t, algorithm: -16, fingerprint: "\0" * 32
    )
    matched = Edhoc::ReceivedCredential.new(
      kind: :x5t, algorithm: -16,
      fingerprint: OpenSSL::Digest::SHA256.digest(leaf.to_der)
    )
    expect(rejected.authenticate_peer(context, matched)).to be_nil
    expect(rejected.authenticate_peer(context, mismatched)).to be_nil

    wrong_usage = certificate(
      'wrong-usage', leaf_key, issuer: root, issuer_key: root_key, key_usage: 'keyAgreement'
    )
    expired = certificate(
      'expired', leaf_key,
      issuer: root,
      issuer_key: root_key,
      not_before: Time.now - 3600,
      not_after: Time.now - 60
    )
    [wrong_usage, expired].each do |certificate_value|
      provider = Edhoc::Credentials::X509Provider.new(
        store: certificate_store(root), local: local,
        resolver: ->(*) { [certificate_value] }
      )
      received = Edhoc::ReceivedCredential.new(kind: :kid, identifier: 'certificate')
      expect(provider.authenticate_peer(context, received)).to be_nil
    end

    no_usage = certificate(
      'no-usage', leaf_key, issuer: root, issuer_key: root_key, key_usage: nil
    )
    provider = Edhoc::Credentials::X509Provider.new(
      store: certificate_store(root), local: local, resolver: ->(*) { [no_usage] }
    )
    received = Edhoc::ReceivedCredential.new(kind: :kid, identifier: 'certificate')
    expect(provider.authenticate_peer(context, received)).to be_a(Edhoc::TrustedCredential)
  end

  it 'rejects absent, malformed, and cryptographically incompatible resolved certificates' do
    key = OpenSSL::PKey.generate_key('ED25519')
    cert = certificate('local', key)
    local = Edhoc::LocalCredential.new(
      private_key: key,
      identification: Edhoc::Credentials::X5Chain.new(certificates: [cert])
    )
    context = callback_context
    received = Edhoc::ReceivedCredential.new(kind: :kid, identifier: 'peer')

    provider = Edhoc::Credentials::X509Provider.new(store: OpenSSL::X509::Store.new, local: local)
    expect(provider.authenticate_peer(context, received)).to be_nil

    malformed = Edhoc::Credentials::X509Provider.new(
      store: OpenSSL::X509::Store.new, local: local, resolver: ->(*) { ['bad certificate'] }
    )
    expect(malformed.authenticate_peer(context, received)).to be_nil

    root, = x509_pair
    wrong_curve = OpenSSL::PKey::EC.generate('prime256v1')
    root_key = OpenSSL::PKey.generate_key('ED25519')
    other_root = certificate('other-root', root_key, ca: true)
    wrong_curve_cert = certificate(
      'wrong-curve', wrong_curve, issuer: other_root, issuer_key: root_key
    )
    incompatible = Edhoc::Credentials::X509Provider.new(
      store: certificate_store(other_root), local: local, resolver: ->(*) { [wrong_curve_cert] }
    )
    expect(incompatible.authenticate_peer(context, received)).to be_nil
    expect(root).to be_a(OpenSSL::X509::Certificate)
  end
end
