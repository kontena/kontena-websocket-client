module Kontena::Websocket
  class Error < StandardError

  end

  class ConnectError < Error

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
end
