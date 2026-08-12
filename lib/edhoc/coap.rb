module Edhoc
  # RFC 9528 Appendix A.2 framing helpers for EDHOC carried over CoAP.
  module CoAP
    module_function

    def prepend_flow(message)
      Native.coap_prepend_flow(String(message).b)
    end

    def extract_flow(payload)
      Native.coap_extract_flow(String(payload).b)
    end

    def prepend_connection_id(message, connection_id)
      Native.coap_prepend_connection_id(String(message).b, connection_id)
    end

    def extract_connection_id(payload)
      Native.coap_extract_connection_id(String(payload).b)
    end

    def connection_id_equal?(left, right)
      Native.coap_connection_id_equal(left, right)
    end
  end
end
