require 'openssl'

module Kontena::Websocket
  class Error < StandardError

  end

  # Unable to establish connection to server
  class ConnectError < Error

  end

  # The server sent something invalid, may not be a http/ws server
  class ProtocolError < Error

  end

  # Unable to establish SSL connection to server
  class SSLConnectError < ConnectError

  end

  # Unable to establish SSL connection to server when using ssl_verif: true
  class SSLVerifyError < SSLConnectError
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

  class SocketError < Error

  end

  # Server closed connection without sending close frame
  class EOFError < SocketError

  end

  # connect/read/write timed out
  class TimeoutError < Error

  end
end
