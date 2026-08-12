require 'openssl'

module CertificateTestHelpers
  def certificate(subject, key, **options)
    issuer = options[:issuer]
    issuer_key = options[:issuer_key]
    ca_certificate = options.fetch(:ca, false)
    key_usage = options.fetch(:key_usage, 'digitalSignature')
    result = OpenSSL::X509::Certificate.new
    result.version = 2
    result.serial = subject.bytes.sum
    result.subject = OpenSSL::X509::Name.parse("/CN=#{subject}")
    result.issuer = issuer ? issuer.subject : result.subject
    result.public_key = key
    result.not_before = options.fetch(:not_before, Time.now - 60)
    result.not_after = options.fetch(:not_after, Time.now + 3600)
    add_certificate_extensions(result, issuer || result, ca_certificate, key_usage)
    result.sign(issuer_key || key, nil)
    result
  end

  def x509_pair
    root_key = OpenSSL::PKey.generate_key('ED25519')
    root = certificate('root', root_key, ca: true)
    initiator_key = OpenSSL::PKey.generate_key('ED25519')
    responder_key = OpenSSL::PKey.generate_key('ED25519')
    initiator_certificate = certificate(
      'initiator', initiator_key, issuer: root, issuer_key: root_key
    )
    responder_certificate = certificate(
      'responder', responder_key, issuer: root, issuer_key: root_key
    )
    [root, initiator_key, initiator_certificate, responder_key, responder_certificate]
  end

  def certificate_store(root)
    OpenSSL::X509::Store.new.tap { |store| store.add_cert(root) }
  end

  private

  def add_certificate_extensions(certificate, issuer, ca_certificate, key_usage)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = certificate
    factory.issuer_certificate = issuer
    certificate.add_extension(
      factory.create_extension('basicConstraints', ca_certificate ? 'CA:TRUE' : 'CA:FALSE', true)
    )
    usage = ca_certificate ? 'keyCertSign,cRLSign' : key_usage
    certificate.add_extension(factory.create_extension('keyUsage', usage, true)) if usage
  end
end
