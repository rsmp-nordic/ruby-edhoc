module Edhoc
  # Convenience preset for a generic session offering only suite 0.
  class Suite0Session < Session
    def initialize(**options)
      raise ArgumentError, 'cipher_suites is fixed for Suite0Session' if options.key?(:cipher_suites)

      super(**options, cipher_suites: [0])
    end
  end
end
