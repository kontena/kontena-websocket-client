# WebSocket::Driver.client(...) API
class Kontena::Websocket::Client::Connection
  include Kontena::Websocket::Logging

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
    debug "wait read: timeout=#{timeout}"
    @socket.wait_readable(timeout) or raise Kontena::Websocket::TimeoutError, "read timeout after #{timeout}s"
    retry
  rescue IO::WaitWritable
    debug "wait write: timeout=#{timeout}"
    @socket.wait_writable(timeout) or raise Kontena::Websocket::TimeoutError, "write timeout after #{timeout}s"
    retry
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
