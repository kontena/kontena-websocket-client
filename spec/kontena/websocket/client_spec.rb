require 'kontena-websocket-client'

describe Kontena::Websocket::Client do
  subject { described_class.new('ws://socket.example.com') }

  describe '#initialize' do
    it "fails with an invalid URL" do
      expect{described_class.new('http://example.com')}.to raise_error(ArgumentError, 'Invalid websocket URL: http://example.com')
    end

    it "initializes state" do
      expect(subject.connected?).to be false
      expect(subject.open?).to be false
    end

    it "parses a ws:// URL" do
      subject = described_class.new('ws://socket.example.com')

      expect(subject.url).to eq 'ws://socket.example.com'
      expect(subject.scheme).to eq 'ws'
      expect(subject.ssl?).to be false
      expect(subject.ssl_verify?).to be false
      expect(subject.host).to eq 'socket.example.com'
      expect(subject.port).to eq 80
    end

    it "parses a wss:// URL" do
      subject = described_class.new('wss://socket.example.com')

      expect(subject.url).to eq 'wss://socket.example.com'
      expect(subject.scheme).to eq 'wss'
      expect(subject.ssl?).to be true
      expect(subject.ssl_verify?).to be false
      expect(subject.host).to eq 'socket.example.com'
      expect(subject.port).to eq 443
    end

    it "parses a ws:// URL with a port" do
      subject = described_class.new('ws://socket.example.com:9292')

      expect(subject.url).to eq 'ws://socket.example.com:9292'
      expect(subject.scheme).to eq 'ws'
      expect(subject.ssl?).to be false
      expect(subject.ssl_verify?).to be false
      expect(subject.host).to eq 'socket.example.com'
      expect(subject.port).to eq 9292
    end
  end

  describe '#ssl_cert' do
    it "fails when not connected" do
      expect{subject.ssl_cert}.to raise_error(RuntimeError, "not connected")
    end
  end
  describe '#ssl_cert!' do
    it "fails when not connected" do
      expect{subject.ssl_cert!}.to raise_error(RuntimeError, "not connected")
    end
  end

  describe '#with_driver' do
    it "fails when not connected" do
      expect{subject.ping}.to raise_error(RuntimeError, "not connected")
    end
  end

  context "with a connection" do
    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }

    before do
      subject.instance_variable_set('@socket', socket)
      subject.instance_variable_set('@connection', connection)
    end

    describe '#start' do
      let(:driver) { instance_double(WebSocket::Driver::Client) }

      it "registers callbacks and starts the handshake" do
        expect(WebSocket::Driver).to receive(:client).with(connection).and_return(driver)

        expect(driver).to receive(:on).with(:error)
        expect(driver).to receive(:on).with(:open)
        expect(driver).to receive(:on).with(:message)
        expect(driver).to receive(:on).with(:close)
        expect(driver).to receive(:start).and_return(true)

        expect(subject.start).to eq driver
      end

      it "fails if driver start does" do
        expect(WebSocket::Driver).to receive(:client).with(connection).and_return(driver)

        expect(driver).to receive(:on).with(:error)
        expect(driver).to receive(:on).with(:open)
        expect(driver).to receive(:on).with(:message)
        expect(driver).to receive(:on).with(:close)
        expect(driver).to receive(:start).and_return(false)

        expect{subject.start}.to raise_error(RuntimeError)
      end
    end

    # XXX: not an unit test, depends on the actual WebSocket::Driver implementation
    context 'with a real driver' do
      before do
        allow(connection).to receive(:url).and_return(subject.url)
        allow(connection).to receive(:write)

        driver = subject.start

        subject.instance_variable_set('@driver', driver)
      end

      let(:driver) do
        subject.instance_variable_get('@driver')
      end

      it "registers an error callback that raises" do
        expect{driver.emit(:error, RuntimeError.new('test'))}.to raise_error(RuntimeError, 'test')
      end

      it "registers an open callback that sets @open" do
        expect{
          driver.emit(:open, double())
        }.to change{subject.open?}.from(false).to(true)
      end

      it "registers a message callback that pushes to @queue" do
        message = nil
        subject.listen do |m|
          message = m
        end

        expect{
          driver.emit(:message, double(data: 'test'))
          subject.process_queue
        }.to change{message}.from(nil).to('test')
      end

      it "registers an close callback that sets @closed" do
        expect{
          driver.emit(:close, double(code: 1337, reason: "test"))
        }.to change{subject.closed?}.from(false).to(true)

        expect(subject.close_code).to eq 1337
        expect(subject.close_reason).to eq 'test'
      end
    end
  end

  context 'with an SSL connection' do
    subject { described_class.new('wss://socket.example.com') }

    let(:socket) { instance_double(OpenSSL::SSL::SSLSocket) }
    let(:cert) { instance_double(OpenSSL::X509::Certificate) }

    before do
      subject.instance_variable_set('@socket', socket)
    end

    describe '#ssl_cert' do
      it "returns the peer cert" do
        expect(socket).to receive(:peer_cert).and_return(cert)

        expect(subject.ssl_cert).to eq cert
      end
    end

    describe '#ssl_cert!' do
      it "fails on verify result" do
        expect(socket).to receive(:verify_result).and_return(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)

        expect{subject.ssl_cert!}.to raise_error(Kontena::Websocket::SSLVerifyError, "certificate verify failed: V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT")
      end

      it "fails if post_connection_check" do
        expect(socket).to receive(:verify_result).and_return(OpenSSL::X509::V_OK)
        expect(socket).to receive(:post_connection_check).and_raise(OpenSSL::SSL::SSLError, 'hostname "192.168.66.1" does not match the server certificate')

        expect{subject.ssl_cert!}.to raise_error(Kontena::Websocket::SSLVerifyError, 'hostname "192.168.66.1" does not match the server certificate')
      end

      it "returns the peer cert if valid" do
        expect(socket).to receive(:verify_result).and_return(OpenSSL::X509::V_OK)
        expect(socket).to receive(:post_connection_check).with('socket.example.com')
        expect(socket).to receive(:peer_cert).and_return(cert)

        expect(subject.ssl_cert!).to eq cert
      end
    end
  end

  context "with a connected driver" do
    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }
    let(:driver) { instance_double(WebSocket::Driver::Client) }

    let(:mutex) { subject.instance_variable_get('@mutex') }

    before do
      subject.instance_variable_set('@socket', socket)
      subject.instance_variable_set('@connection', connection)
      subject.instance_variable_set('@driver', driver)
    end

    describe '#connected' do
      it "is connected" do
        expect(subject.connected?).to be true
      end
    end

    describe '#ssl_cert' do
      it "returns nil when not an SSL connection" do
        expect(subject.ssl_cert).to be nil
      end
    end
    describe '#ssl_cert!' do
      it "returns nil when not an SSL connection" do
        expect(subject.ssl_cert).to be nil
      end
    end

    describe '#with_driver' do
      it "locks the mutex and yields the driver" do
        expect(mutex).to_not be_locked

        expect{subject.with_driver do
          expect(mutex).to be_locked
          expect(mutex).to be_owned

          fail 'test'
        end}.to raise_error(RuntimeError, 'test')

        expect(mutex).to_not be_locked
      end
    end

    describe '#http_status' do
      let(:status) { 200 }

      it "returns the driver status" do
        expect(driver).to receive(:status).and_return(status)

        expect(subject.http_status).to eq status
      end
    end

    describe '#http_headers' do
      let(:headers) { WebSocket::Driver::Headers.new({'X-Test' => '1'}) }

      it "returns the driver status" do
        expect(driver).to receive(:headers).and_return(headers)

        expect(subject.http_headers).to eq headers
      end
    end

    describe '#send' do
      it "fails with invalid type" do
        expect{subject.send(false)}.to raise_error ArgumentError, "Invalid type: FalseClass"
      end

      it "sends text string" do
        expect(driver).to receive(:text).with('asdf').and_return(true)

        subject.send('asdf')
      end

      it "sends binary array" do
        expect(driver).to receive(:binary).with([1, 2]).and_return(true)

        subject.send([1, 2])
      end

      it "fails if driver returns false" do
        expect(driver).to receive(:binary).with([1, 2]).and_return(false)

        expect{subject.send([1, 2])}.to raise_error(RuntimeError)
      end
    end

    describe '#ping' do
      it "sends ping with defaults and no block" do
        expect(driver).to receive(:ping).with('').and_return(true)

        subject.ping
      end

      it "sends ping with message and callback" do
        # XXX: how to expect block?
        expect(driver).to receive(:ping).with('1').and_return(true)

        subject.ping('1') do
          # pong
        end
      end

      it "fails if driver returns false" do
        expect(driver).to receive(:ping).and_return(false)

        expect{subject.ping}.to raise_error(RuntimeError)
      end
    end

    describe '#close' do
      it "closes with defaults" do
        expect(driver).to receive(:close).with(nil, 1000).and_return(true)

        subject.close

        expect(subject.closing?).to be true
      end

      it "closes with code and reason" do
        expect(driver).to receive(:close).with("nope", 4020).and_return(true)

        subject.close(4020, "nope")

        expect(subject.closing?).to be true
      end

      it "fails if driver returns false" do
        expect(driver).to receive(:close).and_return(false)

        expect{subject.close}.to raise_error(RuntimeError)

        expect(subject.closing?).to be false
      end
    end

    describe '#read' do
      it "reads from socket and passes it to locked driver for parsing" do
        expect(connection).to receive(:read).with(Integer, timeout: nil).and_return('asdf')
        expect(driver).to receive(:parse).with('asdf') do
          expect(mutex).to be_locked.and be_owned
        end

        subject.read
      end
    end

    describe '#disconnect' do
      it "closes the socket and resets the state" do
        expect(subject).to be_connected

        expect(socket).to receive :close

        subject.disconnect

        expect(subject).to_not be_connected
      end
    end
  end

  context 'for a ws:// url' do
    let(:url) { 'ws://socket.example.com/'}
    subject { described_class.new(url) }

    let(:tcp_socket) { instance_double(TCPSocket) }

    describe '#connect_tcp' do
      it "connects using the right host and port, and with a connect timeout" do
        expect(Socket).to receive(:tcp).with('socket.example.com', 80, connect_timeout: 60.0).and_return(tcp_socket)

        socket = subject.connect_tcp

        expect(socket).to eq tcp_socket
      end
    end

    context 'without a connect timeout' do
      subject { described_class.new(url, connect_timeout: nil) }

      describe '#connect_tcp' do
        it "does not use a connect timeout" do
          expect(Socket).to receive(:tcp).with('socket.example.com', 80, connect_timeout: nil).and_return(tcp_socket)

          socket = subject.connect_tcp

          expect(socket).to eq tcp_socket
        end
      end
    end

    describe '#connect' do
      it "calls connect_tcp an returns a Connection for the socket" do
        expect(subject).to receive(:connect_tcp).with(no_args).and_return(tcp_socket)

        connection = subject.connect

        expect(connection.url).to eq url

        expect(tcp_socket).to receive(:write_nonblock).with('asdf').and_return(4)
        connection.write('asdf')
      end
    end
  end

  context 'for a wss:// url' do
    let(:url) { 'wss://socket.example.com/'}
    subject { described_class.new(url) }

    let(:tcp_socket) { instance_double(TCPSocket) }
    let(:ssl_socket) { instance_double(OpenSSL::SSL::SSLSocket) }

    before do
      allow(subject).to receive(:connect_tcp).and_return(tcp_socket)
    end

    describe '#ssl_context' do
      it "uses valid defaults" do
        ssl_context = subject.ssl_context

        expect(ssl_context).to be_a OpenSSL::SSL::SSLContext
        expect(ssl_context.verify_mode).to eq OpenSSL::SSL::VERIFY_NONE
      end
    end

    describe '#connect_ssl' do
      it "connects with SNI, but does not verify" do
        expect(OpenSSL::SSL::SSLSocket).to receive(:new).with(tcp_socket, OpenSSL::SSL::SSLContext).and_return(ssl_socket)

        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect_nonblock)
        expect(ssl_socket).to_not receive(:post_connection_check)

        expect(subject.connect_ssl).to eq ssl_socket
      end
    end

    describe '#connect' do
      it "calls connect_ssl and returns a Connection for the socket" do
        expect(subject).to receive(:connect_ssl).with(no_args).and_return(ssl_socket)

        connection = subject.connect

        expect(connection.url).to eq url

        expect(ssl_socket).to receive(:write_nonblock).with('asdf').and_return(4)
        connection.write('asdf')
      end
    end
  end

  context "for a wss:// URL with ssl_verify" do
    let(:url) { 'wss://socket.example.com/'}
    subject { described_class.new(url, ssl_verify: true) }

    let(:tcp_socket) { instance_double(TCPSocket) }
    let(:ssl_socket) { instance_double(OpenSSL::SSL::SSLSocket) }

    before do
      allow(subject).to receive(:connect_tcp).and_return(tcp_socket)
    end

    it 'is ssl?' do
      expect(subject.ssl?).to be true
    end
    it 'is ssl_verify?' do
      expect(subject.ssl_verify?).to be true
    end

    describe '#ssl_context' do
      it "configures verify_mode" do
        ssl_context = subject.ssl_context

        expect(ssl_context).to be_a OpenSSL::SSL::SSLContext
        expect(ssl_context.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
        expect(ssl_context.cert_store).to eq OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
      end
    end

    describe '#connect_ssl' do
      it "connects with SNI, and verifies" do
        expect(OpenSSL::SSL::SSLSocket).to receive(:new).with(tcp_socket, OpenSSL::SSL::SSLContext).and_return(ssl_socket)

        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect)
        expect(ssl_socket).to receive(:post_connection_check)

        expect(subject.connect_ssl).to eq ssl_socket
      end
    end
  end

  context "for a wss:// URL with ssl_ca_file" do
    let(:url) { 'wss://socket.example.com/'}
    subject { described_class.new(url, ssl_ca_file: '/etc/kontena-agent/ca.pem') }

    describe '#ssl_context' do
      it "configures ca_file" do
        ssl_context = subject.ssl_context

        expect(ssl_context).to be_a OpenSSL::SSL::SSLContext
        expect(ssl_context.ca_file).to eq '/etc/kontena-agent/ca.pem'
      end
    end
  end

  context "for a wss:// URL with ssl_ca_path" do
    let(:url) { 'wss://socket.example.com/'}
    subject { described_class.new(url, ssl_ca_path: '/etc/kontena-agent/ca.d') }

    describe '#ssl_context' do
      it "configures ca_path" do
        ssl_context = subject.ssl_context

        expect(ssl_context).to be_a OpenSSL::SSL::SSLContext
        expect(ssl_context.ca_path).to eq '/etc/kontena-agent/ca.d'
      end
    end
  end

  describe '#run' do
    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }
    let(:driver) { instance_double(WebSocket::Driver::Client) }

    before do
      allow(subject).to receive(:connect) do
        subject.instance_variable_set('@socket', socket)
        connection
      end
      allow(subject).to receive(:start) do
        subject.started!

        driver
      end
    end

    it "calls open block once, processes messages, and raises on close" do
      opened = messages = 0
      subject.listen do |message|
        messages += 1
      end

      expect(connection).to receive(:read).with(Integer, timeout: Float).and_return('foo')
      expect(driver).to receive(:parse).with('foo') do
        subject.on_open double()
      end

      expect(connection).to receive(:read).with(Integer, timeout: nil).and_return('bar')
      expect(driver).to receive(:parse).with('bar') do
        subject.on_message double(data: 'data')
      end

      expect(connection).to receive(:read).with(Integer, timeout: nil).and_raise(EOFError)

      expect(socket).to receive(:close)

      expect{
        subject.run do
          opened += 1
        end
      }.to raise_error(Kontena::Websocket::EOFError)

      expect(opened).to eq 1
      expect(messages).to eq 1
    end

    it 'closes the socket on errors' do
      expect(subject).to receive(:start).and_raise(ArgumentError, 'something went wrong')
      expect(socket).to receive(:close)

      expect{
        subject.run
      }.to raise_error(ArgumentError)
    end

    it 'survives errors' do
      expect(subject).to receive(:connect).and_raise(Kontena::Websocket::ConnectError)

      expect{
        subject.run
      }.to raise_error(Kontena::Websocket::ConnectError)
    end
  end
end
