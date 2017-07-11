require 'websocket/driver'
require 'forwardable'
require 'socket'
require 'openssl'

# Threadsafe: while the #run method is reading/parsing incoming websocket frames, the #send/#ping/#close methods
# can be called by other threads. The #listen and #ping blocks will be called from the #run thread.
#
class Kontena::Websocket::Client
  require_relative './client/connection'

  include Kontena::Websocket::Logging

  attr_reader :uri

  FRAME_SIZE = 4 * 1024
  CONNECT_TIMEOUT = 60.0
  OPEN_TIMEOUT = 60.0
  PING_INTERVAL = 60.0
  PING_TIMEOUT = 10.0
  CLOSE_TIMEOUT = 60.0
  WRITE_TIMEOUT = 60.0

  # @param [String] url
  # @param headers [Hash{String => String}]
  # @param ssl_version [OpenSSL::SSL::SSLContext::METHODS] :SSLv23, :SSLv3, :TLSv1, :TLSv1_1, :TLSv1_2
  # @param ssl_verify [Boolean] verify peer cert, host
  # @param ssl_ca_file [String] path to CA cert bundle file
  # @param ssl_ca_path [String] path to hashed CA cert directory
  # @param connect_timeout [Float]
  # @param open_timeout [Float] expect server open frame after start()
  # @param ping_interval [Float] send pings every interval seconds
  # @param ping_timeout [Float] expect pong response after timeout seconds
  # @param close_timeout [Float] expect server close frame after close()
  # @param write_timeout [Float] throttle when sending faster than the server is able to receive, fail if no progress is made
  # @raise [ArgumentError] Invalid websocket URI
  def initialize(url, headers: {},
      ssl_version: :SSLv23,
      ssl_verify: nil,
      ssl_ca_file: nil,
      ssl_ca_path: nil,
      connect_timeout: CONNECT_TIMEOUT,
      open_timeout: OPEN_TIMEOUT,
      ping_interval: PING_INTERVAL,
      ping_timeout: PING_TIMEOUT,
      close_timeout: CLOSE_TIMEOUT,
      write_timeout: WRITE_TIMEOUT
  )
    @uri = URI.parse(url)
    @headers = headers
    @ssl_verify = ssl_verify
    @ssl_params = {
      ssl_version: ssl_version,
      ca_file: ssl_ca_file,
      ca_path: ssl_ca_path,
      verify_mode: ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE,
    }
    @connect_timeout = connect_timeout
    @open_timeout = open_timeout
    @ping_interval = ping_interval
    @ping_timeout = ping_timeout
    @close_timeout = close_timeout
    @write_timeout = write_timeout

    unless @uri.scheme == 'ws' || @uri.scheme == 'wss'
      raise ArgumentError, "Invalid websocket URL: #{@uri}"
    end

    @mutex = Mutex.new # for @driver

    # written by #enqueue from @driver callbacks with the @mutex held
    # drained by #process_queue from #run -> #read_loop without the @mutex held
    @queue = []

    # sequential ping-pongs
    @ping_id = 0
    @ping_at = Time.now # fake for first ping_interval
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

  # Connecting with SSL cert/host verification?
  # @return [Boolean]
  def ssl_verify?
    !!@ssl_verify
  end

  # @return [String]
  def host
    @uri.host
  end

  # @return [Integer]
  def port
    @uri.port || (@uri.scheme == "ws" ? 80 : 443)
  end

  # Register block to pass received messages to.
  #
  # @yield [message] received websocket message payload
  # @yieldparam message [String, Array<integer>] text or binary
  def on_message(&block)
    @on_message = block
  end

  # Connected to server. Not necessarily open yet.
  #
  # @return [Boolean]
  def connected?
    !!@socket && !!@connection && !!@driver
  end

  # Client has started websocket handshake, but is not yet open.
  #
  # @return [Boolean]
  def starting?
    !!@started_at && !@open
  end

  # Server has accepted websocket connection.
  #
  # @return [Boolean]
  def open?
    !!@open
  end

  # Client has sent close frame, but socket is not yet closed.
  #
  # @return [Boolean]
  def closing?
    !!@closing && !@closed
  end

  # Server has closed websocket connection.
  #
  # @return [Boolean]
  def closed?
    !!@closed
  end

  # Valid once #run returns, when closed?
  #
  # @return [Integer]
  def close_code
    @close_code
  end

  # Valid once #run returns, when closed?
  #
  # @return [String]
  def close_reason
    @close_reason
  end

  # Connect, send websocket handshake, and loop reading responses.
  #
  # Passed block is called once websocket is open.
  # Raises on errors.
  # Returns once websocket is closed by server.
  #
  # Intended to be called using a dedicated per-websocket thread.
  # Other threads can then call the other threadsafe methods:
  #  * send
  #  * ping
  #  * close
  #
  # @yield [] websocket open
  # @raise [Kontena::Websocket::ConnectError]
  # @raise [Kontena::Websocket::ProtocolError]
  # @raise [Kontena::Websocket::CloseError] connection closed by server
  # @return websocket closed by server
  def run(&block)
    @on_open = block

    @connection = self.connect
    @driver = self.start

    while !@closed
      read_state, state_start, state_timeout = self.read_state_timeout

      if state_timeout
        read_deadline = state_start + state_timeout
        read_timeout = read_deadline - Time.now
      else
        read_timeout = nil
      end

      begin
        # read and process frames with @driver @mutex held
        self.read(read_timeout)
      rescue Kontena::Websocket::TimeoutError => exc
        if read_state == :ping
          self.ping
        elsif read_state
          raise exc.class.new("#{exc} while waiting #{state_timeout}s for #{read_state}")
        else
          raise
        end
      end

      # call @queue blocks with the lock released
      self.process_queue
    end

  ensure
    # ensure socket is closed and client disconnected on any of:
    #   * start error
    #   * read error
    #   * read EOF
    self.disconnect
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
  # @raise [Kontena::Websocket::SSLVerifyError]
  # @return [nil] not an ssl connection
  # @return [OpenSSL::X509::Certificate]
  def ssl_cert!
    fail "not connected" unless @socket
    return nil unless ssl?

    x509_verify_result = @socket.verify_result

    unless x509_verify_result == OpenSSL::X509::V_OK
      raise Kontena::Websocket::SSLVerifyError.from_verify_result(x509_verify_result)
    end

    begin
      # checks peer cert exists, and validates CN
      @socket.post_connection_check(self.host)
    rescue OpenSSL::SSL::SSLError => exc
      raise Kontena::Websocket::SSLVerifyError.new(exc.message)
    end

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

  # Send message frame, either text or binary.
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

  # Register pong handler.
  # Called from the #read thread every ping_interval after received pong.
  #
  # The ping interval should be longer than the ping timeout.
  # If new pings are sent before old pings get any response, then the older pings do not yield on pong.
  #
  # @yield [delay] received pong
  # @yieldparam delay [Float] ping-pong delay in seconds
  def on_pong(&block)
    @on_pong = block
  end

  # Send ping.
  #
  # @raise [RuntimeError] not connected
  def ping
    with_driver do |driver|
      ping_id = @ping_id += 1

      debug "pinging with id=#{ping_id}"

      fail unless driver.ping(ping_id.to_s) do
        debug "pong with id=#{ping_id}"

        # resolve ping timeout, unless this pong is late and we already sent a new one
        # called with @mutex held
        if ping_id == @ping_id
          pinged!
          ping_delay = @ping_delay

          debug "ping-pong with id=#{ping_id} in #{ping_delay}s"

          # queue to call block without @mutex held
          enqueue { @on_pong.call(ping_delay) } if @on_pong
        end
      end

      # must be called from #read loop to use the right read timeout
      pinging!
    end
  end

  # Start read deadline for @ping_timeout
  def pinging!
    @pinging = true
    @ping_at = Time.now
    @pong_at = nil
  end

  # Waiting for pong from ping
  #
  # @return [Boolean]
  def pinging?
    !!@pinging
  end

  # Stop read deadline for @ping_timeout
  def pinged!
    @pinging = false
    @pong_at = Time.now
    @ping_delay = @pong_at - @ping_at
  end

  # Measured ping-pong delay from previous ping
  #
  # nil if not pinged yet
  #
  # @return [Float, nil]
  def ping_delay
    @ping_delay
  end

  # Send close frame. Waits for server to send back close frame, and then raises
  # from #run with a close error.
  #
  # TODO: close timeout
  # XXX: prevent sending other frames after close?
  #
  # @param close [Integer]
  # @param reason [String]
  def close(code = 1000, reason = nil)
    debug "close"

    with_driver do |driver|
      fail unless driver.close(reason, code) # swapped argument order

      closing!
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

  # Called from @driver callbacks with the @mutex held
  #
  # Queues block for call from #process_queue
  def enqueue(&block)
    fail unless block

    @queue << block
  end

  # Called from read_loop without the @mutex held
  #
  def process_queue
    while block = @queue.shift
      block.call
    end
  end

  # Connect to TCP server.
  #
  # @raise [Kontena::Websocket::TimeoutError] Errno::ETIMEDOUT
  # @raise [Kontena::Websocket::ConnectError] Errno::*
  # @return [TCPSocket]
  def connect_tcp
    debug "connect_tcp: timeout=#{@connect_timeout}"

    Socket.tcp(self.host, self.port, connect_timeout: @connect_timeout)
  rescue Errno::ETIMEDOUT => exc
    raise Kontena::Websocket::TimeoutError, "Connect timeout after #{@connect_timeout}s" # XXX: actual delay
  rescue SystemCallError => exc
    raise Kontena::Websocket::ConnectError, exc
  end

  # @return [OpenSSL::SSL::SSLContext]
  def ssl_context
    ssl_context = OpenSSL::SSL::SSLContext.new()
    ssl_context.set_params(**@ssl_params)
    ssl_context
  end

  # TODO: connect_deadline to impose a single deadline on the entire process
  # XXX: specs
  #
  # @param ssl_socket [OpenSSL::SSL::SSLSocket]
  # @raise [Kontena::Websocket::TimeoutError]
  def ssl_connect(ssl_socket)
    debug "ssl_connect..."
    ret = ssl_socket.connect_nonblock
  rescue IO::WaitReadable
    debug "ssl_connect wait read: timeout=#{@connect_timeout}"
    ssl_socket.wait_readable(@connect_timeout) or raise Kontena::Websocket::TimeoutError
    retry
  rescue IO::WaitWritable
    debug "ssl_connect wait write: timeout=#{@connect_timeout}"
    ssl_socket.wait_writable(@connect_timeout) or raise Kontena::Websocket::TimeoutError
    retry
  else
    debug "ssl_connect: #{ret}"
  end

  # Connect to TCP server, perform SSL handshake, verify if required.
  #
  # @raise [Kontena::Websocket::ConnectError] from connect_tcp
  # @raise [Kontena::Websocket::SSLConnectError]
  # @raise [Kontena::Websocket::SSLVerifyError] errors that only happen with ssl_verify: true
  # @return [OpenSSL::SSL::SSLSocket]
  def connect_ssl
    tcp_socket = self.connect_tcp
    ssl_context = self.ssl_context

    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
    ssl_socket.sync_close = true # close TCPSocket after SSL shutdown
    ssl_socket.hostname = self.host # SNI

    begin
      self.ssl_connect(ssl_socket)
    rescue OpenSSL::SSL::SSLError => exc
      if exc.message.end_with? 'certificate verify failed'
        raise Kontena::Websocket::SSLVerifyError.from_verify_result(ssl_socket.verify_result)
      else
        raise Kontena::Websocket::SSLConnectError, exc
      end
    end

    begin
      ssl_socket.post_connection_check(self.host) if @ssl_verify
    rescue OpenSSL::SSL::SSLError => exc
      raise Kontena::Websocket::SSLVerifyError.new(exc.message)
    end

    ssl_socket
  end

  # Create @socket and return connection wrapper.
  #
  # @raise [Kontena::Websocket::ConnectError]
  # @return [Connection]
  def connect
    if ssl?
      @socket = self.connect_ssl
    else
      @socket = self.connect_tcp
    end

    return Connection.new(@uri, @socket,
      write_timeout: @write_timeout,
    )
  end

  # Create websocket driver using @connection, and send websocket handshake
  # Must be connected.
  # Registers driver handlers to set @open, @closed states, enqueue messages, or raise errors.
  #
  # @raise [RuntimeError] already started?
  # @return [WebSocket::Driver::Client]
  def start
    driver = ::WebSocket::Driver.client(@connection)

    @headers.each do |k, v|
      driver.set_header(k, v)
    end

    # these are called from read_loop -> with_driver { driver.parse } with the @mutex held
    # do not recurse back into with_driver!
    driver.on :error do |event|
      self.on_driver_error(event)
    end

    driver.on :open do |event|
      self.on_driver_open(event)
    end

    driver.on :message do |event|
      self.on_driver_message(event)
    end

    driver.on :close do |event|
      self.on_driver_close(event)
    end

    # not expected to emit anything, not even :error
    fail unless driver.start

    started!

    return driver
  end

  # @param exc [WebSocket::Driver::ProtocolError]
  def on_driver_error(exc)
    # this will presumably propagate up out of #recv_loop, not this function
    raise exc

  rescue WebSocket::Driver::ProtocolError => exc
    raise Kontena::Websocket::ProtocolError, exc
  end

  # Mark client as opened, calling the block passed to #run.
  #
  # @param event [WebSocket::Driver::OpenEvent] no attrs
  def on_driver_open(event)
    @open = true
    enqueue { @on_open.call } if @on_open
  end

  # Queue up received messages
  # Causes #read_loop -> #process_messages to dequeue and yield to @listen_block
  #
  # @param event [WebSocket::Driver::MessageEvent] data
  def on_driver_message(event)
    enqueue { @on_message.call(event.data) } if @on_message
  end

  # Mark client as closed, allowing #run to return (and disconnect from the server).
  #
  # @param event [WebSocket::Driver::CloseEvent] code, reason
  def on_driver_close(event)
    @closed = true
    @close_code = event.code
    @close_reason = event.reason
  end

  # Start read deadline for @open_timeout
  def started!
    @started_at = Time.now
  end

  # Start read deadline for @open_timeout
  def closing!
    @closing = true
    @closing_at = Time.now
  end

  # Return read deadline for current read state
  #
  # @return [Symbol, Float, Float] state, time, timeout
  def read_state_timeout
    case
    when starting? && @open_timeout
      [:open, @started_at, @open_timeout]
    when pinging? && @ping_timeout
      [:pong, @ping_at, @ping_timeout]
    when closing? && @close_timeout
      [:close, @closing_at, @close_timeout]
    when @ping_interval
      [:ping, @ping_at, @ping_interval]
    else
      [nil, nil, nil]
    end
  end

  # Read from socket, and parse websocket frames, enqueue blocks.
  # The websocket must be connected.
  #
  # @param timeout [Flaot] seconds
  # @raise [Kontena::Websocket::TimeoutError] read deadline expired
  # @raise [Kontena::Websocket::TimeoutError] read timeout after X.Ys
  # @raise [Kontena::Websocket::SocketError]
  def read(timeout = nil)
    if timeout && timeout <= 0.0
      raise Kontena::Websocket::TimeoutError, "read deadline expired"
    end

    begin
      data = @connection.read(FRAME_SIZE, timeout: timeout)

    rescue EOFError => exc
      debug "read EOF"

      raise Kontena::Websocket::EOFError, 'Server closed connection without sending close frame'

    rescue IOError => exc
      # socket was closed => IOError: closed stream
      debug "read IOError: #{exc}"

      raise Kontena::Websocket::SocketError, exc

    # TODO: Errno::ECONNRESET etc
    end

    with_driver do |driver|
      # call into the driver, causing it to emit the events registered in #start
      driver.parse(data)
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

    # TODO: errors and timeout? SSLSocket.close in particular is bidirectional?
    @socket.close if @socket
    @socket = nil
  end
end
