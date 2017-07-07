require 'websocket/driver'
require 'forwardable'
require 'socket'
require 'openssl'

class Kontena::Websocket::Client
  require_relative './client/connection'

  include Kontena::Websocket::Logging

  attr_reader :uri

  FRAME_SIZE = 4 * 1024
  CLOSE_NORMAL = 1000
  CLOSE_ABNORMAL = 1006

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
      raise ArgumentError, "Invalid websocket URL: #{@uri}"
    end

    @mutex = Mutex.new # for @driver
    @recv_queue = []
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

  # Connect, send websocket handshake, and loop reading responses.
  #
  # Yield once websocket is open.
  # Raises an error.
  # Returns once websocket is closed by server.
  #
  # Intended to be called using a dedicated per-websocket thread.
  # Other threads can then call the other threadsafe methods:
  #  * send
  #  * ping
  #  * close
  #
  # @yield [] websocket open
  # @raise
  # @raise [Kontena::Websocket::CloseError]
  # @return websocket closed by server
  def run(&block)
    @open_block = block

    @connection = self.connect
    @driver = self.start

    self.read_loop(@socket)

    raise @close_error unless @close_error.code == CLOSE_NORMAL

  ensure
    # ensure socket is closed and client disconnected on any of:
    #   * start error
    #   * read error
    #   * read EOF
    self.disconnect
  end

  def connected?
    !!@socket && !!@connection && !!@driver
  end

  def open?
    !!@open
  end

  # @raise [RuntimeError] not connected
  # @return [nil] not an ssl connection, or no peer cert
  # @return [OpenSSL::X509::Certificate]
  def ssl_cert
    fail "not connected" unless @socket
    return nil unless ssl?

    return @socket.peer_cert
  end

  # Verify and return SSL cert. Validates even if not ssl_verify.
  #
  # @raise [RuntimeError] not connected
  # @raise [OpenSSL::SSL::SSLError]
  # @return [nil] not an ssl connection
  # @return [OpenSSL::X509::Certificate]
  def ssl_cert!
    fail "not connected" unless @socket
    return nil unless ssl?

    x509_verify_result = @socket.verify_result

    unless x509_verify_result == OpenSSL::X509::V_OK
      raise Kontena::Websocket::SSLVerifyError.new(x509_verify_result)
    end

    # checks peer cert exists, and validates CN
    # raises OpenSSL::SSL::SSLError
    @socket.post_connection_check(self.host)

    return @socket.peer_cert
  end

  # Valid once open
  #
  # @return [Integer]
  def http_status
    with_driver do |driver|
      driver.status
    end
  end

  # Valid once open
  #
  # @return [Websocket::Driver::Headers]
  def http_headers
    with_driver do |driver|
      driver.headers
    end
  end

  # Valid once open
  #
  # @yield [message] received websocket message payload
  # @yieldparam message [String, Array<integer>] text or binary
  def listen(&block)
    @listen_block = block
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
      with_driver do |driver|
        fail unless driver.text(message)
      end
    when Array
      with_driver do |driver|
        fail unless driver.binary(message)
      end
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
    with_driver do |driver|
      fail unless driver.ping(string, &cb)
    end
  end

  # Send close frame.
  #
  # XXX: threadsafe vs concurrent @driver.parse etc?
  # TODO: close timeout
  #
  # Eventually emits on :close, which will disconnect!
  def close(code = 1000, reason = nil)
    debug "close"

    with_driver do |driver|
      fail unless driver.close(reason, code) # swapped argument order
    end
  end

#protected XXX: called by specs

  # Call into driver with locked Mutex
  #
  # @raise [RuntimeError] not connected
  # @yield [driver]
  # @yieldparam driver [Websocket::Driver]
  def with_driver
    fail "not connected" unless @driver

    @mutex.synchronize {
      yield @driver
    }
  end

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
    ssl_socket.post_connection_check(self.host) if @ssl_verify # XXX: should raise SSLVerifyError
    ssl_socket

  rescue OpenSSL::SSL::SSLError => exc
    if exc.message.end_with? 'state=error: certificate verify failed'
      raise Kontena::Websocket::SSLVerifyError.new(ssl_socket.verify_result)
    else
      raise
    end
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

    return Connection.new(@uri, @socket)
  end

  # Create @driver and send websocket handshake
  # Must be connected.
  # Registers driver handlers to set @open, @recv_queue, @close state or raise errors
  #
  # @raise [RuntimeError] XXX: already started?
  def start
    driver = ::WebSocket::Driver.client(@connection)

    @headers.each do |k, v|
      driver.set_header(k, v)
    end

    # these are called from read_loop -> with_driver { driver.parse } with the @mutex held
    # do not recurse back into with_driver!
    driver.on :error do |event|
      self.on_error(event)
    end

    driver.on :open do |event|
      self.on_open(event)
    end

    driver.on :message do |event|
      self.on_message(event)
    end

    driver.on :close do |event|
      self.on_close(event)
    end

    # not expected to emit anything, not even :error
    fail unless driver.start

    return driver
  end

  # @param exc [WebSocket::Driver::URIError]
  def on_error(exc)
    debug "#{url} error: #{exc} @\n\t#{caller.join("\n\t")}"

    # this will presumably propagate up out of #recv_loop, not this function
    raise exc
  end

  # Mark client as opened.
  # Causes #read_loop to call @open_block.
  #
  # @param event [WebSocket::Driver::OpenEvent] no attrs
  def on_open(event)
    debug "#{url} open @\n\t#{caller.join("\n\t")}"

    @open = true
  end

  # Queue up received messages
  # Causes #read_loop -> #process_messages to dequeue and yield to @listen_block
  #
  # @param event [WebSocket::Driver::MessageEvent] data
  def on_message(event)
    debug "#{url} message: #{event.data} @\n\t#{caller.join("\n\t")}"

    # XXX: should this be a threadsafe Queue instead?
    @recv_queue << event.data
  end

  # Store the @close_error, and disconnect.
  #
  # Disconnect will close the socket, allowing #read_loop to return.
  #
  # @param event [WebSocket::Driver::CloseEvent] code, reason
  def on_close(event)
    debug "#{url} close: code=#{event.code}, reason=#{event.reason} @\n\t#{caller.join("\n\t")}"

    # store for raise from run()
    @close_error = Kontena::Websocket::CloseError.new(event.code, event.reason)

    # do not wait for server to close
    # results in EOF for #read_loop, which returns
    self.disconnect
  end

  # Loop to read the socket, parse websocket frames, and call user blocks.
  # The websocket must be connected.
  def read_loop(socket)
    loop do
      begin
        data = socket.readpartial(FRAME_SIZE)

      rescue EOFError
        debug "read EOF"

        # if we received on :close, the EOF is expected, and we keep that error
        @close_error ||= Kontena::Websocket::EOFError.new

        # just return, #run will handle disconnect
        return

      rescue IOError => exc
        debug "read IOError: #{exc}"

        # XXX: what is @close_error? What if this is a timeout?
        @close_error ||= Kontena::Websocket::CloseError.new(1006, exc.message)

        # on_close -> disconnect -> socket.close => IOError: closed stream
        return
      end

      with_driver do |driver|
        # call into the driver, causing it to emit the events registered in #start
        driver.parse(data)
      end

      # call user callbacks with the mutex released, so that they are free to call back into send()
      if @open && @open_block
        # only called once
        @open_block.call()
        @open_block = nil
      end

      # yield any parsed messages
      self.process_messages
    end
  end

  def process_messages
    while message = @recv_queue.shift
      @listen_block.call(message)
    end
  end

  # Clear connection state, close socket
  #
  # This gets called from:
  # * run ensure
  # * on :close
  #
  # This means that this can get called twice:
  # * Server sends close frame: read -> on :close -> disconnect
  # * Socket is closed: read EOF -> run ensure -> disconnect
  def disconnect
    debug "disconnect"

    @open = false
    @driver = nil
    @connection = nil

    # XXX: raises?
    # XXX: timeout?
    @socket.close if @socket
    @socket = nil
  end
end
