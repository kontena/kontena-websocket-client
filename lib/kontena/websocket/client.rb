require 'websocket/driver'
require 'forwardable'
require 'socket'
require 'openssl'

# Threadsafe: while the #run method is reading/parsing incoming websocket frames, the #send/#ping/#close methods
# can be called by other threads.
# The #run (on_open), #on_message and #on_pong blocks will be called from the #run thread.
#
#
=begin example
   def websocket_connect
      @ws = Kontena::Websocket::Client.new(url, ...)
      @ws.on_message do |message|
        actor.on_message(message)
      end

      # connecting
      @ws.run do
        # connected
        actor.on_open
      end
      actor.on_close(@ws.close_code, @ws.close_reason)
    rescue Kontena::Websocket::Error => exc
      actor.on_error(exc)
    ensure
      # disconnected
      @ws = nil
    end
  end
=end
class Kontena::Websocket::Client
  require_relative './client/connection'

  include Kontena::Websocket::Logging

  attr_reader :uri

  FRAME_SIZE = 4 * 1024
  CONNECT_TIMEOUT = 60.0
  OPEN_TIMEOUT = 60.0
  PING_INTERVAL = 60.0
  PING_TIMEOUT = 10.0
  PING_STRFTIME = '%FT%T.%NZ' # high-percision RFC 3339
  CLOSE_TIMEOUT = 60.0
  WRITE_TIMEOUT = 60.0

  # @param [String] url
  # @param headers [Hash{String => String}]
  # @param ssl_params [Hash] @see OpenSSL::SSL::SSLContext
  #   The DEFAULT_PARAMS includes verify_mode: OpenSSL::SSL::VERIFY_PEER.
  #   Use { verify_mode: OpenSSL::SSL::VERIFY_NONE } to disable Kontena::Websocket::SSLVerifyError on connect.
  # @param ssl_hostname [String] override hostname for SSL SNI, certificate identity matching
  # @param connect_timeout [Float] timeout for TCP handshake; XXX: each phase of the SSL handshake
  # @param open_timeout [Float] expect open frame after #start
  # @param ping_interval [Float] send pings every interval seconds after previous ping
  # @param ping_timeout [Float] expect pong frame after #ping
  # @param close_timeout [Float] expect close frame after #close
  # @param write_timeout [Float] block #send when sending faster than the server is able to receive, fail if no progress is made
  # @raise [ArgumentError] Invalid websocket URI
  def initialize(url, headers: {},
      ssl_params: {},
      ssl_hostname: nil,
      connect_timeout: CONNECT_TIMEOUT,
      open_timeout: OPEN_TIMEOUT,
      ping_interval: PING_INTERVAL,
      ping_timeout: PING_TIMEOUT,
      close_timeout: CLOSE_TIMEOUT,
      write_timeout: WRITE_TIMEOUT
  )
    @uri = URI.parse(url)
    @headers = headers
    @ssl_params = ssl_params
    @ssl_hostname = ssl_hostname

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
  #
  # @return [Boolean]
  def ssl_verify?
    ssl? && ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
  end

  # @return [String]
  def ssl_hostname
    @ssl_hostname || @uri.host
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
  #  * close
  #
  # @yield [] websocket open
  # @raise [Kontena::Websocket::ConnectError]
  # @raise [Kontena::Websocket::ProtocolError]
  # @raise [Kontena::Websocket::TimeoutError]
  # @return websocket closed by server, @see #close_code #close_reason
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
          debug "ping on #{exc}"
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

    # raises Kontena::Websocket::SSLVerifyError
    self.ssl_verify_cert! @socket.peer_cert, @socket.peer_cert_chain

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

  # Send ping message.
  #
  # This is intended to be automatically called from #run per @ping_interval.
  # Calling it from the #run callbacks also works, but calling it from a different thread
  # while #run is blocked on read() will ignore the @ping_timeout, unless the server happens
  # to send something else.
  #
  # @raise [RuntimeError] not connected
  def ping
    with_driver do |driver|
      # must be called from #read loop to use the right read timeout
      ping_at = pinging!

      debug "pinging at #{ping_at}"

      fail unless driver.ping(ping_at.utc.strftime(PING_STRFTIME)) do
        debug "pong for #{ping_at}"

        # resolve ping timeout, unless this pong is late and we already sent a new one
        # called with @mutex held
        if ping_at == @ping_at
          ping_delay = pinged!

          debug "ping-pong at #{ping_at} in #{ping_delay}s"

          # queue to call block without @mutex held
          enqueue { @on_pong.call(ping_delay) } if @on_pong
        end
      end

    end
  end

  # Waiting for pong from ping
  #
  # @return [Boolean]
  def pinging?
    !!@pinging
  end

  # Measured ping-pong delay from previous ping
  #
  # nil if not pinged yet
  #
  # @return [Float, nil]
  def ping_delay
    @ping_delay
  end

  # Send close frame. Waits for server to send back close frame, and then allows #run to return.
  # Imposes a close timeout when called from #run blocks (run/on_message/on_pong do ...). If called from
  # a different thread, then #run should eventually return, once either:
  # * server sends close frame
  # * server sends any other frame after the close timeout expires
  # * the ping interval expires
  #
  # XXX: prevent #send after close?
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

#protected XXX: called by specs TODO: refactor out to separate TCP/SSL client classes

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
  # @raise [Kontena::Websocket::ConnectError] SocketError
  # @return [TCPSocket]
  def connect_tcp
    debug "connect_tcp: timeout=#{@connect_timeout}"

    Socket.tcp(self.host, self.port, connect_timeout: @connect_timeout)
  rescue Errno::ETIMEDOUT => exc
    raise Kontena::Websocket::TimeoutError, "Connect timeout after #{@connect_timeout}s" # XXX: actual delay
  rescue SocketError => exc
    raise Kontena::Websocket::ConnectError, exc
  rescue SystemCallError => exc
    raise Kontena::Websocket::ConnectError, exc
  end

  # @raise [ArgumentError] Failed adding cert store file/path: ...
  # @return [OpenSSL::X509::Store]
  def ssl_cert_store
    @ssl_cert_store ||= OpenSSL::X509::Store.new.tap do |ssl_cert_store|
      ca_file = @ssl_params[:ca_file] || ENV['SSL_CERT_FILE']
      ca_path = @ssl_params[:ca_path] || ENV['SSL_CERT_PATH']

      if ca_file || ca_path
        if ca_file
          debug "add cert store file: #{ca_file}"

          begin
            ssl_cert_store.add_file ca_file
          rescue OpenSSL::X509::StoreError
            raise ArgumentError, "Failed adding cert store file: #{ca_file}"
          end
        end

        if ca_path
          debug "add cert store path: #{ca_path}"

          begin
            # XXX: does not actually raise
            ssl_cert_store.add_path ca_path
          rescue OpenSSL::X509::StoreError
            raise ArgumentError, "Failed adding cert store path: #{ca_path}"
          end
        end
      else
        debug "use default cert store paths"

        ssl_cert_store.set_default_paths
      end
    end
  end

  # @param ssl_cert [OpenSSL::X509::Certificate]
  # @raise [Kontena::Websocket::SSLVerifyError]
  def ssl_verify_cert!(ssl_cert, ssl_cert_chain)
    unless ssl_cert
      raise Kontena::Websocket::SSLVerifyError.new(OpenSSL::X509::V_OK, ssl_cert, ssl_cert_chain), "No certificate"
    end

    ssl_verify_context = OpenSSL::X509::StoreContext.new(ssl_cert_store, ssl_cert, ssl_cert_chain)

    unless ssl_verify_context.verify
      raise Kontena::Websocket::SSLVerifyError.new(ssl_verify_context.error, ssl_cert, ssl_cert_chain), ssl_verify_context.error_string
    end

    unless OpenSSL::SSL.verify_certificate_identity(ssl_cert, self.ssl_hostname)
      raise Kontena::Websocket::SSLVerifyError.new(OpenSSL::X509::V_OK, ssl_cert, ssl_cert_chain), "Subject does not match hostname #{self.ssl_hostname}: #{ssl_cert.subject}"
    end
  end

  # @param verify_result [Integer] OpenSSL::SSL::SSLSocket#verify_result
  # @return [Kontena::Websocket::SSLVerifyError]
  def ssl_verify_error(verify_result, ssl_cert = nil, ssl_cert_chain = nil)
    ssl_verify_context = OpenSSL::X509::StoreContext.new(ssl_cert_store)
    ssl_verify_context.error = verify_result

    Kontena::Websocket::SSLVerifyError.new(ssl_verify_context.error, ssl_cert, ssl_cert_chain, ssl_verify_context.error_string)
  end

  # @return [OpenSSL::SSL::SSLContext]
  def ssl_context
    @ssl_context ||= OpenSSL::SSL::SSLContext.new().tap do |ssl_context|
      ssl_context.set_params(**@ssl_params,
        cert_store: self.ssl_cert_store,
      )
    end
  end

  # TODO: connect_deadline to impose a single deadline on the entire process
  # XXX: specs
  #
  # @param ssl_socket [OpenSSL::SSL::SSLSocket]
  # @raise [OpenSSL::SSL::SSLError]
  # @raise [Kontena::Websocket::TimeoutError]
  def ssl_connect(ssl_socket)
    debug "ssl_connect..."
    ret = ssl_socket.connect_nonblock
  rescue IO::WaitReadable
    debug "ssl_connect wait read: timeout=#{@connect_timeout}"
    ssl_socket.wait_readable(@connect_timeout) or raise Kontena::Websocket::TimeoutError, "SSL connect read timeout after #{@connect_timeout}s"
    retry
  rescue IO::WaitWritable
    debug "ssl_connect wait write: timeout=#{@connect_timeout}"
    ssl_socket.wait_writable(@connect_timeout) or raise Kontena::Websocket::TimeoutError, "SSL connect write timeout after #{@connect_timeout}s"
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

    debug "connect_ssl: #{ssl_context.inspect} hostname=#{self.ssl_hostname}"

    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
    ssl_socket.sync_close = true # close TCPSocket after SSL shutdown
    ssl_socket.hostname = self.ssl_hostname # SNI

    begin
      self.ssl_connect(ssl_socket)
    rescue OpenSSL::SSL::SSLError => exc
      # SSL_connect returned=1 errno=0 state=error: certificate verify failed
      if exc.message.end_with? 'certificate verify failed'
        # ssl_socket.peer_cert is not set on errors :(
        raise ssl_verify_error(ssl_socket.verify_result)
      else
        raise Kontena::Websocket::SSLConnectError, exc
      end
    end

    # raises Kontena::Websocket::SSLVerifyError
    self.ssl_verify_cert!(ssl_socket.peer_cert, ssl_socket.peer_cert_chain) if ssl_verify?

    ssl_socket
  end

  # Create @socket and return connection wrapper.
  #
  # @raise [Kontena::Websocket::ConnectError]
  # @raise [Kontena::Websocket::TimeoutError]
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

    started! # start @open_timeout

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

  # Start read deadline for @ping_timeout
  #
  # @return [Time] ping at
  def pinging!
    @pinging = true
    @ping_at = Time.now
    @pong_at = nil

    @ping_at
  end

  # Stop read deadline for @ping_timeout
  # @return [Float] ping delay
  def pinged!
    @pinging = false
    @pong_at = Time.now
    @ping_delay = @pong_at - @ping_at

    @ping_delay
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
