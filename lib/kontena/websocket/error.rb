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
    # @param verify_result [Integer] @see OpenSSL::SSL::SSLSocket#verify_result
    def initialize(verify_result, message = nil)
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
