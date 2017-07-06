require 'websocket/driver'
require 'forwardable'
require 'socket'
require 'openssl'

class Kontena::Websocket::Client
  require_relative './client/connection'

  extend Forwardable
  include Kontena::Logging

  attr_reader :uri

  FRAME_SIZE = 4 * 1024
  X509_VERIFY_ERRORS = OpenSSL::X509.constants.grep(/^V_(ERR_|OK)/).map { |name| [OpenSSL::X509.const_get(name), name] }.to_h

  # @param [String] url
  # @param headers [Hash{String => String}]
  # @param ssl_version [OpenSSL::SSL::SSLContext::METHODS] :SSLv23, :SSLv3, :TLSv1, :TLSv1_1, :TLSv1_2
  # @param ssl_verify [Boolean] verify peer cert, host
  # @param ssl_ca_file [String] path to CA cert bundle file
  # @param ssl_ca_path [String] path to hashed CA cert directory
  # @raise [ArgumentError] Invalid websocket URI
  def initialize(url, headers: {}, ssl_version: :SSLv23, ssl_verify: nil, ssl_ca_file: nil, ssl_ca_path: nil)
    @uri = URI.parse(url)
    @headers = headers
    @ssl_verify = ssl_verify
    @ssl_params = {
      ssl_version: ssl_version,
      ca_file: ssl_ca_file,
      ca_path: ssl_ca_path,
      verify_mode: ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE,
    }

    unless @uri.scheme == 'ws' || @uri.scheme == 'wss'
      raise ArgumentError, "Invalid websocket URI: #{@uri}"
    end
  end

  # @return [String]
  def url
    @uri.to_s
  end

  # @return [String] ws or wss
  def scheme
    @uri.scheme
  end

  # @return [Boolean]
  def ssl?
    @uri.scheme == 'wss'
  end

  def host
    @uri.host
  end

  # @return [Integer]
  def port
    @uri.port || (@uri.scheme == "ws" ? 80 : 443)
  end

  # Connect, send websocket handshake, and loop reading responses to emit events.
  #
  # Intended to be called using a dedicated per-websocket thread.
  # Other threads can then call the other threadsafe methods:
  #  * send
  #  * ping
  #
  # @raise
  def run(&block)
    self.connect
    self.start(&block)
    self.read_loop
  end

  # @raise [ArgumentError] Not connected
  # @return [nil] not an ssl connection, or no peer cert
  # @return [OpenSSL::X509::Certificate]
  def ssl_cert
    raise ArgumentError, "Not connected" unless @socket
    return nil unless ssl?

    return @socket.peer_cert
  end

  # Verify and return SSL cert. Validates even if not ssl_verify.
  #
  # @raise [ArgumentError] Not connected
  # @raise [OpenSSL::SSL::SSLError]
  # @return [nil] not an ssl connection
  # @return [OpenSSL::X509::Certificate]
  def ssl_cert!
    raise ArgumentError, "Not connected" unless @socket
    return nil unless ssl?

    x509_verify = @socket.verify_result

    unless x509_verify == OpenSSL::X509::V_OK
      raise OpenSSL::SSL::SSLError, "certificate verify failed: #{X509_VERIFY_ERRORS[x509_verify]}"
    end

    # checks peer cert exists, and validates CN
    # raises OpenSSL::SSL::SSLError
    @socket.post_connection_check(self.host)

    return @socket.peer_cert
  end

  # Valid after on :open
  #
  # @return [Integer]
  def http_status
    @driver.status
  end

  # Valid after on :open
  #
  # @return [Websocket::Driver::Headers]
  def http_headers
    @driver.headers
  end

  # Send message frame, either text or binary.
  #
  # XXX: threadsafe vs concurrent @driver.parse etc?
  #
  # @param message [String, Array<Integer>]
  # @raise [ArgumentError] invalid type
  # @raise [RuntimeError] unable to send (socket closed?)
  def send(message)
    case message
    when String
      fail unless @driver.text(message)
    when Array
      fail unless @driver.binary(message)
    else
      raise ArgumentError, "Invalid type: #{message.class}"
    end
  end

  # Send ping. Register optional callback, called from the #read thread.
  #
  # XXX: threadsafe vs concurrent @driver.parse etc?
  #
  # @param string [String]
  # @yield [] received pong
  # @raise [RuntimeError]
  def ping(string = '', &cb)
    fail unless @driver.ping(string, &cb)
  end

  # Send close frame.
  #
  # XXX: threadsafe vs concurrent @driver.parse etc?
  #
  # Eventually emits on :close, which will disconnect!
  def close
    fail unless @driver.close
  end

protected

  # Connect to TCP server.
  #
  # @raise [SystemCallError]
  # @return [TCPSocket]
  def connect_tcp
    ::TCPSocket.new(self.host, self.port)
  end

  # @return [OpenSSL::SSL::SSLContext]
  def ssl_context
    ssl_context = OpenSSL::SSL::SSLContext.new()
    ssl_context.set_params(**@ssl_params)
    ssl_context
  end

  # Connect to TCP server, perform SSL handshake, verify if required.
  #
  # @raise [OpenSSL::SSL::SSLError]
  # @return [OpenSSL::SSL::SSLSocket]
  def connect_ssl
    tcp_socket = self.connect_tcp
    ssl_context = self.ssl_context

    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
    ssl_socket.sync_close = true # XXX: also close TCPSocket
    ssl_socket.hostname = self.host # SNI
    ssl_socket.connect
    ssl_socket.post_connection_check(self.host) if @ssl_verify
    ssl_socket
  end

  # Create @socket and @connection
  #
  # @raise [SystemCallError]
  # @raise [OpenSSL::SSL::SSLError]
  # @return [Connection]
  def connect
    if ssl?
      @socket = self.connect_ssl
    else
      @socket = self.connect_tcp
    end

    @connection = Connection.new(@uri, @socket)
  end

  # Create @driver and send websocket handshake once connected
  # Yields driver for registering handlers, before starting.
  #
  # Allows #read to emit :open later.
  # XXX:May emit :error?
  #
  # @raise [RuntimeError] XXX: already started?
  # @yield [ws_driver]
  # @yieldparam ws_driver [Websocket::Driver]
  def start(&block)
    @driver = ::WebSocket::Driver.client(@connection)

    @headers.each do |k, v|
      @driver.set_header(k, v)
    end

    @driver.on :error do |err|
      debug "#{url} error: #{err} @\n\t#{caller.join("\n\t")}"

      raise err
    end

    @driver.on :open do
      debug "#{url} open @\n\t#{caller.join("\n\t")}"
    end

    @driver.on :message do |data|
      debug "#{url} message: #{data.inspect} @\n\t#{caller.join("\n\t")}"
    end

    @driver.on :close do |code, reason|
      debug "#{url} close: code=#{code}, reason=#{reason} @\n\t#{caller.join("\n\t")}"

      # close and cleanup socket
      self.disconnect
    end

    yield @driver

    # XXX: might emit :error?
    fail unless @driver.start

  rescue => exc
    # cleanup on errors
    @driver = nil

    # XXX: racy if the driver also emits :close?
    self.disconnect

    # XXX: these should be emit :error instead?
    raise
  end

  # Loop to read and parse websocket frames.
  # The websocket must be connected.
  #
  # The thread calling this method will also emit websocket events.
  def read_loop
    loop do
      begin
        data = @socket.readpartial(FRAME_SIZE)
      rescue EOFError
        # XXX: fail @driver?
        break
      end

      @driver.parse(data)
    end
  end

  # Clear connection state, close socket.
  def disconnect
    @driver = nil
    @connection = nil

    @socket.close if @socket
  end
end
