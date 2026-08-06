module Edhoc
  # Convenience preset for a generic session offering only suite 4.
  class Suite4Session < Session
    def initialize(**options)
      raise ArgumentError, 'cipher_suites is fixed for Suite4Session' if options.key?(:cipher_suites)

      super(**options, cipher_suites: [4])
    end
  end
end
