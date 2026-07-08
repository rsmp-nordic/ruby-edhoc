module Edhoc
  # Stateful EDHOC suite 4 handshake session backed by libedhoc.
  class Suite4Session < Suite0Session
    private

    def build_native_session(options)
      Native::Suite4Session.new(*native_session_arguments(options))
    end
  end
end
