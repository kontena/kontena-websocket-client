require 'openssl'

module Kontena::Websocket
  class Error < StandardError

  end

  class ConnectError < Error

  end

  class SSLError < ConnectError

  end

  class SSLVerifyError < SSLError
    X509_VERIFY_RESULTS = OpenSSL::X509.constants.grep(/^V_(ERR_|OK)/).map { |name| [OpenSSL::X509.const_get(name), name] }.to_h

    def self.from_verify_result(verify_result)
      new("certificate verify failed: #{X509_VERIFY_RESULTS[verify_result]}", verify_result)
    end

    # @param verify_result [Integer] @see OpenSSL::SSL::SSLSocket#verify_result
    def initialize(message, verify_result = nil)
      super(message)
      @verify_result = verify_result
    end
  end

  class CloseError < Error
    attr_reader :code, :reason

    def initialize(code, reason)
      super("Connection closed with code #{code}: #{reason}")
      @code = code
      @reason = reason
    end

    def normal?
      @code == 1000
    end
  end

  class EOFError < CloseError
    def initialize
      super(1006, "EOF")
    end
  end
end
