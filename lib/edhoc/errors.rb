module Edhoc
  class Error < StandardError
  end

  # Base class for errors returned by libedhoc. Native errors expose stable
  # symbolic and numeric metadata so callers do not need to parse messages.
  class NativeError < Error
    attr_reader :operation, :code, :code_number, :protocol_code

    def local_cipher_suites = @local_cipher_suites&.reverse
    def peer_cipher_suites = @peer_cipher_suites&.reverse
  end

  class BadStateError < NativeError
  end

  class InvalidArgumentError < NativeError
  end

  class NotSupportedError < NativeError
  end

  class NotPermittedError < NativeError
  end

  class BufferTooSmallError < NativeError
  end

  class NativeMemoryError < NativeError
  end

  class CborError < NativeError
  end

  class CryptoError < NativeError
  end

  class CredentialsError < NativeError
  end

  class EadError < NativeError
  end

  class KeyExchangeError < NativeError
  end

  class MessageError < NativeError
  end
end
