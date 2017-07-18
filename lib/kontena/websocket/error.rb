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

  # Unable to establish SSL connection to server when using ssl_verify: true
  class SSLVerifyError < SSLConnectError
    attr_reader :cert, :cert_chain

    # @param verify_result [Integer] @see OpenSSL::SSL::SSLSocket#verify_result
    # @param cert [OpenSSL::X509::Certificate]
    # @param cert_chain [Array<OpenSSL::X509::Certificate>]
    # @param message [String]
    def initialize(verify_result, cert = nil, cert_chain = nil, message = nil)
      super(message)
      @verify_result = verify_result
      @cert = cert
      @cert_chain = cert_chain
    end

    def subject
      @cert.subject
    end

    def issuer
      @cert.issuer
    end

    def to_s
      "certificate verify failed: #{super}"
    end
  end

  class SocketError < Error

  end

  # connect/read/write timed out
  class TimeoutError < Error

  end

  # server closed connection
  class CloseError < Error
    attr_reader :code, :reason

    def initialize(code, reason = nil)
      super(reason)
      @code = code
      @reason = reason
    end

    def to_s
      "connection closed with code #{@code}: #{super}"
    end
  end

  # Server closed connection without sending close frame
  class EOFError < CloseError
    def initialize(message = nil)
      super(1006, message)
    end
  end
end
