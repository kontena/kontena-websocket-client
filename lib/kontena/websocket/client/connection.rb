# WebSocket::Driver.client(...) API
class Kontena::Websocket::Client::Connection
  include Kontena::Websocket::Logging

  # ruby version >= 2.3
  module Waitable
    # @param socket [Socket]
    # @param timeout [Float] default (nil) blocks indefinitely
    # @raise [Kontena::Websocket::TimeoutError]
    def wait_socket_readable!(socket, timeout = nil)
      debug "wait read: timeout=#{timeout}"

      unless @socket.wait_readable(timeout)
        raise Kontena::Websocket::TimeoutError, "read timeout after #{timeout}s"
      end
    end

    # @param socket [Socket]
    # @param timeout [Float] default (nil) blocks indefinitely
    # @raise [Kontena::Websocket::TimeoutError]
    def wait_socket_writable!(socket, timeout = nil)
      debug "wait write: timeout=#{timeout}"

      unless @socket.wait_writable(timeout)
        raise Kontena::Websocket::TimeoutError, "write timeout after #{timeout}s"
      end
    end
  end

  # ruby version <= 2.2
  #
  # io/wait IO#wait_readable returns nil on EOF
  module Waitable_Ruby2_2
    # @param socket [Socket]
    # @param timeout [Float] default (nil) blocks indefinitely
    # @raise [Kontena::Websocket::TimeoutError]
    def wait_socket_readable!(socket, timeout = nil)
      debug "wait read: timeout=#{timeout}"

      unless IO.select([socket], nil, nil, timeout)
        raise Kontena::Websocket::TimeoutError, "read timeout after #{timeout}s"
      end
    end

    # @param socket [Socket]
    # @param timeout [Float] default (nil) blocks indefinitely
    # @raise [Kontena::Websocket::TimeoutError]
    def wait_socket_writable!(socket, timeout = nil)
      debug "wait write: timeout=#{timeout}"

      unless IO.select(nil, [socket], nil, timeout)
        raise Kontena::Websocket::TimeoutError, "write timeout after #{timeout}s"
      end
    end
  end

  if Kontena::Websocket::Client.ruby_version? '2.3'
    require 'io/wait'
    include Waitable
  else
    include Waitable_Ruby2_2
  end

  attr_reader :uri

  # @param uri [URI]
  # @param socket [TCPSocket, OpenSSL::SSL::SSLSocket]
  # @param write_timeout [Float] per each write syscall
  def initialize(uri, socket, write_timeout: nil)
    @uri = uri
    @socket = socket
    @write_timeout = write_timeout
  end

  # @return [String]
  def url
    @uri.to_s
  end

  # Wait up to timeout before retrying any blocking operation.
  #
  # @param timeout [Float] default (nil) blocks indefinitely
  # @raise [Kontena::Websocket::TimeoutError]
  def nonblocking_timeout(timeout = nil, &block)
    return yield
  rescue IO::WaitReadable
    wait_socket_readable!(@socket, timeout) # raises Kontena::Websocket::TimeoutError
    retry
  rescue IO::WaitWritable
    wait_socket_writable!(@socket, timeout) # raises Kontena::Websocket::TimeoutError
    retry
  end

  # @param size [Integer]
  # @param timeout [Float]
  # @raise [EOFError]
  # @return [String] 0..size bytes
  def read(size, timeout: nil)
    buf = nonblocking_timeout(timeout) do
      @socket.read_nonblock(size)
    end

    debug "read size=#{size}: #buf=#{buf.size}"

    return buf
  end

  # @param buf [String]
  def write(buf)
    until buf.empty?
      # it can take more than the timeout to write out the entire buffer
      size = nonblocking_timeout(@write_timeout) do
        @socket.write_nonblock(buf)
      end
      debug "write #buf=#{buf.size}: size=#{size}"
      buf = buf[size..-1]
    end
  end
end
