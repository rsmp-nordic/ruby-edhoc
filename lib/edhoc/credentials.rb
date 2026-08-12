require 'openssl'

module Edhoc
  module Credentials
    # A credential referenced by a raw or CBOR-encoded COSE KID.
    class KID
      FORMATS = %i[raw cbor].freeze

      attr_reader :identifier, :credential, :format

      def initialize(identifier:, credential:, format: :raw)
        @identifier = String(identifier).b.freeze
        raise ArgumentError, 'KID identifier must not exceed 32 bytes' if @identifier.bytesize > 32

        @credential = String(credential).b.freeze
        @format = format.to_sym
        raise ArgumentError, 'KID format must be :raw or :cbor' unless FORMATS.include?(@format)

        freeze
      end
    end

    # A leaf-first X.509 certificate chain sent with the handshake.
    class X5Chain
      attr_reader :certificates

      def initialize(certificates:)
        @certificates = Array(certificates).map { |certificate| Certificate.der(certificate) }.freeze
        raise ArgumentError, 'x5chain must contain one to three certificates' unless (1..3).cover?(@certificates.length)

        freeze
      end
    end

    # A certificate referenced by its COSE x5t thumbprint.
    class X5T
      attr_reader :algorithm, :fingerprint, :certificate

      def initialize(algorithm:, fingerprint:, certificate:)
        @algorithm = normalize_algorithm(algorithm)
        @fingerprint = String(fingerprint).b.freeze
        raise ArgumentError, 'x5t fingerprint must not exceed 64 bytes' if @fingerprint.bytesize > 64

        @certificate = Certificate.der(certificate).freeze
        freeze
      end

      private

      def normalize_algorithm(value)
        if value.is_a?(String)
          result = value.b.freeze
          raise ArgumentError, 'x5t algorithm name must not exceed 32 bytes' if result.bytesize > 32

          result
        else
          Integer(value).tap do |integer|
            raise RangeError, 'x5t algorithm must fit int32' unless (-(2**31)...(2**31)).cover?(integer)
          end
        end
      end
    end

    # The private key and identification selected for a local callback.
    class LocalCredential
      attr_reader :private_key, :identification

      def initialize(private_key:, identification:)
        unless identification.is_a?(KID) || identification.is_a?(X5Chain) || identification.is_a?(X5T)
          raise ArgumentError, 'identification must be a KID, X5Chain, or X5T'
        end

        @private_key = private_key
        @identification = identification
        freeze
      end
    end

    # The peer identification decoded from an EDHOC message.
    class ReceivedCredential
      attr_reader :kind, :identifier, :credential, :format, :certificates,
                  :algorithm, :fingerprint

      def initialize(values)
        @kind = values.fetch(:kind).to_sym
        @identifier = optional_binary(values[:identifier])
        @credential = optional_binary(values[:credential])
        @format = values[:format]&.to_sym
        @certificates = optional_certificates(values[:certificates])
        @algorithm = values[:algorithm]
        @fingerprint = optional_binary(values[:fingerprint])
        freeze
      end

      private

      def optional_binary(value) = value&.b&.freeze
      def optional_certificates(values) = values&.map { |item| item.b.freeze }&.freeze
    end

    # Credential material accepted by the application trust policy.
    class TrustedCredential
      FORMATS = %i[raw cbor].freeze

      attr_reader :credential, :format, :public_key, :peer_id

      def initialize(credential:, public_key:, format: :raw, peer_id: nil)
        @credential = String(credential).b.freeze
        @format = format.to_sym
        raise ArgumentError, 'trusted credential format must be :raw or :cbor' unless FORMATS.include?(@format)

        @public_key = public_key
        @peer_id = peer_id
        freeze
      end
    end

    # DER normalization helpers shared by credential value classes.
    module Certificate
      module_function

      def der(value)
        return value.to_der.b if value.is_a?(OpenSSL::X509::Certificate)

        OpenSSL::X509::Certificate.new(String(value)).to_der.b
      rescue OpenSSL::X509::CertificateError
        raise ArgumentError, 'certificate must be DER/PEM or OpenSSL::X509::Certificate'
      end

      def parse(value)
        return value if value.is_a?(OpenSSL::X509::Certificate)

        OpenSSL::X509::Certificate.new(String(value))
      end
    end

    # Suite- and authentication-aware validation of OpenSSL and raw keys.
    module KeyMaterial
      ED25519_PKCS8_PREFIX = ['302e020100300506032b657004220420'].pack('H*').freeze
      SUITE_SHAPES = {
        0 => { scalar: 32, signature_public: 32, static_public: 32, curve: nil },
        2 => { scalar: 32, signature_public: 65, static_public: 32, curve: 'prime256v1' },
        4 => { scalar: 32, signature_public: 32, static_public: 32, curve: nil },
        24 => { scalar: 48, signature_public: 97, static_public: 48, curve: 'secp384r1' }
      }.freeze

      module_function

      def private_bytes(value, context)
        shape = shape(context)
        if context.authentication == :signature && [0, 4].include?(context.cipher_suite)
          ed25519_private(value)
        elsif [0, 4].include?(context.cipher_suite) && value.respond_to?(:raw_private_key)
          ensure_oid!(value, 'X25519')
          exact_bytes(value.raw_private_key, shape.fetch(:scalar), 'X25519 private key')
        elsif value.respond_to?(:private_key)
          ec_private(value, shape)
        else
          exact_bytes(value, shape.fetch(:scalar), 'private key')
        end
      end

      def public_bytes(value, context)
        shape = shape(context)
        signature = context.authentication == :signature
        expected = shape.fetch(signature ? :signature_public : :static_public)
        unless value.respond_to?(:public_key) || value.respond_to?(:raw_public_key)
          return raw_public_bytes(value, context, expected)
        end

        if [0, 4].include?(context.cipher_suite)
          curve25519_public(value, context, expected)
        else
          ec_public(value, shape, signature)
        end
      end

      def shape(context)
        SUITE_SHAPES.fetch(context.cipher_suite) do
          raise ArgumentError, "unsupported cipher suite #{context.cipher_suite}"
        end
      end

      def ed25519_private(value)
        if value.respond_to?(:raw_private_key)
          ensure_oid!(value, 'ED25519')
          return exact_bytes(value.raw_private_key, 32, 'Ed25519 private seed') +
                 exact_bytes(value.raw_public_key, 32, 'Ed25519 public key')
        end

        bytes = String(value).b
        return derive_ed25519(bytes) if bytes.bytesize == 32
        unless bytes.bytesize == 64
          raise ArgumentError,
                'Ed25519 private key must be a 32-byte seed or a 64-byte seed-plus-public key'
        end

        validate_ed25519_pair(bytes)
      end

      def derive_ed25519(seed)
        key = OpenSSL::PKey.read(ED25519_PKCS8_PREFIX + seed)
        seed + key.raw_public_key
      rescue OpenSSL::PKey::PKeyError
        raise ArgumentError, 'invalid Ed25519 seed'
      end

      def validate_ed25519_pair(bytes)
        derived_public = derive_ed25519(bytes.byteslice(0, 32)).byteslice(32, 32)
        supplied_public = bytes.byteslice(32, 32)
        unless OpenSSL.fixed_length_secure_compare(derived_public, supplied_public)
          raise ArgumentError, 'Ed25519 seed-plus-public key is inconsistent'
        end

        bytes
      end

      def ec_private(value, shape)
        ensure_ec_curve!(value, shape.fetch(:curve))
        scalar = value.private_key
        raise ArgumentError, 'EC key does not contain private material' unless scalar

        exact_bytes(scalar.to_s(2).rjust(shape.fetch(:scalar), "\0"), shape.fetch(:scalar), 'EC private scalar')
      end

      def curve25519_public(value, context, expected)
        expected_oid = context.authentication == :signature ? 'ED25519' : 'X25519'
        ensure_oid!(value, expected_oid)
        exact_bytes(value.raw_public_key, expected, "#{expected_oid} public key")
      end

      def ec_public(value, shape, signature)
        ensure_ec_curve!(value, shape.fetch(:curve))
        expected = shape.fetch(signature ? :signature_public : :static_public)
        encoded = value.public_key.to_octet_string(:uncompressed)
        encoded = encoded.byteslice(1, expected) unless signature
        exact_bytes(encoded, expected, 'EC public point')
      end

      def raw_public_bytes(value, context, expected)
        bytes = String(value).b
        if context.authentication == :static_dh && [2, 24].include?(context.cipher_suite) &&
           bytes.bytesize == expected + 1 && [2, 3].include?(bytes.getbyte(0))
          return bytes.byteslice(1, expected)
        end

        exact_bytes(bytes, expected, 'public key')
      end

      def ensure_oid!(key, expected)
        actual = key.respond_to?(:oid) ? key.oid.to_s.upcase : ''
        return if actual == expected

        raise ArgumentError,
              "expected #{expected} key, got #{actual.empty? ? key.class : actual}"
      end

      def ensure_ec_curve!(key, expected)
        return if key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == expected

        raise ArgumentError, "expected EC key on #{expected}"
      end

      def exact_bytes(value, length, name)
        bytes = String(value).b
        raise ArgumentError, "#{name} must be #{length} bytes" unless bytes.bytesize == length

        bytes
      end
    end

    # Internal adapter used by the extension. It keeps the public callback API
    # typed while passing bounded byte strings across the Ruby/C boundary.
    class ProviderBridge
      def initialize(provider)
        unless provider.respond_to?(:select_local) && provider.respond_to?(:authenticate_peer)
          raise ArgumentError, 'credentials must implement select_local and authenticate_peer'
        end

        @provider = provider
      end

      def __native_select_local(values)
        context = CallContext.from_native(values)
        selected = @provider.select_local(context)
        raise CredentialsError, 'credential provider returned no local credential' if selected.nil?
        raise TypeError, 'select_local must return LocalCredential' unless selected.is_a?(LocalCredential)

        encode_local(selected, context)
      end

      def __native_authenticate_peer(context_values, received_values)
        context = CallContext.from_native(context_values)
        trusted = @provider.authenticate_peer(context, ReceivedCredential.new(received_values))
        return nil if trusted.nil?
        unless trusted.is_a?(TrustedCredential)
          raise TypeError,
                'authenticate_peer must return TrustedCredential or nil'
        end

        {
          credential: trusted.credential,
          format: trusted.format,
          public_key: KeyMaterial.public_bytes(trusted.public_key, context),
          peer_id: trusted.peer_id
        }
      end

      private

      def encode_local(selected, context)
        identification = selected.identification
        encoded = { private_key: KeyMaterial.private_bytes(selected.private_key, context) }
        case identification
        when KID
          encoded.merge(
            kind: :kid, identifier: identification.identifier,
            credential: identification.credential, format: identification.format
          )
        when X5Chain
          encoded.merge(kind: :x5chain, certificates: identification.certificates)
        when X5T
          encoded.merge(
            kind: :x5t, algorithm: identification.algorithm,
            fingerprint: identification.fingerprint, certificate: identification.certificate
          )
        end
      end
    end

    # Certificate-chain provider. Trust is never implicit: construction requires
    # an application-configured OpenSSL::X509::Store.
    class X509Provider
      def initialize(store:, local:, resolver: nil, policy: nil)
        raise ArgumentError, 'store must be an OpenSSL::X509::Store' unless store.is_a?(OpenSSL::X509::Store)

        @store = store
        @local = local
        @resolver = resolver
        @policy = policy
      end

      def select_local(context)
        credential = @local.respond_to?(:call) ? @local.call(context) : select_from_hash(context)
        return credential if credential.is_a?(LocalCredential)

        raise TypeError, 'X509Provider local selector must return LocalCredential'
      end

      def authenticate_peer(context, received)
        certificates = peer_certificates(context, received)
        return nil if certificates.empty?

        leaf, *intermediates = certificates
        return nil unless @store.verify(leaf, intermediates)
        return nil unless compatible_key_usage?(leaf, context.authentication)
        return nil unless fingerprint_matches?(received, leaf)

        public_key = leaf.public_key
        KeyMaterial.public_bytes(public_key, context)
        policy_result = @policy&.call(context, received, certificates)
        return nil if @policy && !policy_result

        TrustedCredential.new(
          credential: leaf.to_der, public_key: public_key,
          peer_id: policy_result == true ? nil : policy_result
        )
      rescue OpenSSL::OpenSSLError, ArgumentError
        nil
      end

      private

      def select_from_hash(context)
        return @local unless @local.is_a?(Hash)

        @local[context.authentication] || @local[context.authentication.to_s]
      end

      def peer_certificates(context, received)
        values = if received.kind == :x5chain
                   received.certificates
                 elsif @resolver
                   @resolver.call(context, received)
                 end
        Array(values).map { |value| Certificate.parse(value) }
      end

      def fingerprint_matches?(received, leaf)
        return true unless received.kind == :x5t

        digest = fingerprint_digest(received.algorithm)
        expected = digest.digest(leaf.to_der)
        expected = expected.byteslice(0, 8) if received.algorithm == -15
        expected.bytesize == received.fingerprint.bytesize &&
          OpenSSL.fixed_length_secure_compare(expected, received.fingerprint)
      end

      def fingerprint_digest(algorithm)
        name = { -15 => 'SHA256', -16 => 'SHA256', -43 => 'SHA384', -44 => 'SHA512' }[algorithm]
        name ||= String(algorithm)
        OpenSSL::Digest.new(name)
      end

      def compatible_key_usage?(certificate, authentication)
        extension = certificate.extensions.find { |item| item.oid == 'keyUsage' }
        return true unless extension

        required = authentication == :signature ? 'Digital Signature' : 'Key Agreement'
        extension.value.split(',').map(&:strip).include?(required)
      end
    end
  end

  LocalCredential = Credentials::LocalCredential
  ReceivedCredential = Credentials::ReceivedCredential
  TrustedCredential = Credentials::TrustedCredential
end
