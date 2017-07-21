require 'kontena-websocket-client'

RSpec.describe Kontena::Websocket::Client do
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
      expect(subject.ssl_verify?).to be true
      expect(subject.ssl_hostname).to eq 'socket.example.com'
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

  context "with a connecting client" do
    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }

    before do
      allow(subject).to receive(:socket_connect) do
        subject.instance_variable_set('@socket', socket)
        connection
      end
    end

    describe '#connect' do
      let(:driver) { instance_double(WebSocket::Driver::Client) }

      it 'disconnects if websocket open fails' do
        expect(subject).to receive(:websocket_open).with(connection) do
          fail 'open error'
        end

        expect(subject).to_not receive(:websocket_read)
        expect(subject).to receive(:disconnect)

        expect{subject.connect}.to raise_error(RuntimeError, 'open error')
      end

      it 'disconnects if websocket read fails' do
        expect(subject).to receive(:websocket_open).with(connection) do
          driver
        end

        expect(subject).to receive(:websocket_read) do
          fail 'read error'
        end
        expect(subject).to receive(:disconnect)

        expect{subject.connect}.to raise_error(RuntimeError, 'read error')
      end

      it 'connects socket, opens websocket, and reads until open' do
        expect(subject).to receive(:websocket_open).with(connection) do
          driver
        end

        expect(subject).to receive(:websocket_read)
        expect(subject).to receive(:websocket_read) do
          subject.opened!
        end

        expect(subject).to_not receive(:disconnect)

        subject.connect
      end

      it 'returns even if server closes right after opening' do
        expect(subject).to receive(:websocket_open).with(connection) do
          driver
        end

        expect(subject).to receive(:websocket_read)
        expect(subject).to receive(:websocket_read) do
          subject.opened!
          subject.closed! 1005, 'test'
        end

        expect(subject).to_not receive(:disconnect)

        subject.connect
      end
    end
  end

  context "with a connection" do
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }

    describe '#websocket_open' do
      let(:driver) { instance_double(WebSocket::Driver::Client) }

      it "registers callbacks and starts the handshake" do
        expect(WebSocket::Driver).to receive(:client).with(connection).and_return(driver)

        expect(driver).to receive(:on).with(:error)
        expect(driver).to receive(:on).with(:open)
        expect(driver).to receive(:on).with(:message)
        expect(driver).to receive(:on).with(:close)
        expect(driver).to receive(:start).and_return(true)

        expect(subject.websocket_open(connection)).to eq driver
      end

      it "fails if driver start does" do
        expect(WebSocket::Driver).to receive(:client).with(connection).and_return(driver)

        expect(driver).to receive(:on).with(:error)
        expect(driver).to receive(:on).with(:open)
        expect(driver).to receive(:on).with(:message)
        expect(driver).to receive(:on).with(:close)
        expect(driver).to receive(:start).and_return(false)

        expect{subject.websocket_open(connection)}.to raise_error(RuntimeError)
      end
    end

    # XXX: not an unit test, depends on the actual WebSocket::Driver implementation
    context 'with a real driver' do
      before do
        allow(connection).to receive(:url).and_return(subject.url)
        allow(connection).to receive(:write)

        driver = subject.websocket_open(connection)

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

      it "registers a message callback that pushes to @message_queue" do
        message_queue = subject.instance_variable_get('@message_queue')

        driver.emit(:message, double(data: 'test 1'))
        driver.emit(:message, double(data: 'test 2'))

        expect(message_queue).to eq ['test 1', 'test 2']
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
    let(:cert_chain) { [instance_double(OpenSSL::X509::Certificate)] }

    before do
      subject.instance_variable_set('@socket', socket)

      allow(socket).to receive(:peer_cert).and_return(cert)
      allow(socket).to receive(:peer_cert_chain).and_return(cert_chain)
    end

    describe '#ssl_cert' do
      it "returns the socket peer cert" do
        expect(subject.ssl_cert).to eq cert
      end
    end

    describe '#ssl_cert!' do
      it "fails if no peer cert" do
        expect(socket).to receive(:peer_cert).and_return(nil)
        expect(socket).to receive(:peer_cert_chain).and_return(nil)

        expect{subject.ssl_cert!}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: No certificate')
      end

      it "fails if the certificate does not verify" do
        expect(subject).to receive(:ssl_verify_cert!).with(cert, cert_chain).and_raise(Kontena::Websocket::SSLVerifyError.new(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, cert, cert_chain), 'self signed certificate')

        expect{subject.ssl_cert!}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: self signed certificate') do |exc|
          expect(exc.cert).to eq cert
          expect(exc.cert_chain).to eq cert_chain
        end
      end

      it "returns the peer cert if valid" do
        expect(subject).to receive(:ssl_verify_cert!).with(cert, cert_chain)

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

    describe '#read' do
      context 'with a closing websocket with queued messages' do
        before do
          subject.closing! 1005
          subject.on_driver_message double(data: 'test 1')
          subject.on_driver_message double(data: 'test 2')
          subject.on_driver_close double(code: 1005, reason: 'test')
        end

        it 'returns queued messages' do
          expect(subject.read).to eq 'test 1'
          expect(subject.read).to eq 'test 2'
          expect(subject.read).to be nil
        end

        it 'yields queued messages' do
          expect{|block| subject.read(&block) }.to yield_successive_args 'test 1', 'test 2'
        end
      end

      context 'with a closed websocket with queued messages' do
        before do
          subject.on_driver_message double(data: 'test 1')
          subject.on_driver_message double(data: 'test 2')
          subject.on_driver_close double(code: 1005, reason: 'test')
        end

        it 'returns queued messages before failing with CloseError' do
          expect(subject.read).to eq 'test 1'
          expect(subject.read).to eq 'test 2'
          expect{subject.read}.to raise_error(Kontena::Websocket::CloseError, 'connection closed with code 1005: test')
        end

        it 'yields queued messages' do
          expect{|block| subject.read(&block) }.to yield_successive_args('test 1', 'test 2').and raise_error(Kontena::Websocket::CloseError, 'connection closed with code 1005: test')
        end
      end

      context 'with queued messags' do
        before do
          subject.on_driver_message double(data: 'test 1')
          subject.on_driver_message double(data: 'test 2')
        end

        it 'returns queued messages, before reading more' do
          expect(subject.read).to eq 'test 1'
          expect(subject.read).to eq 'test 2'

          expect(subject).to receive(:websocket_read) do
            subject.on_driver_message double(data: 'test 3')
          end

          expect(subject.read).to eq 'test 3'
        end

        it 'yields queued messages, before reading more' do
          i = 0

          subject.read do |msg|
            case i += 1
            when 1
              expect(msg).to eq 'test 1'
            when 2
              expect(msg).to eq 'test 2'
              expect(subject).to receive(:websocket_read) do
                subject.on_driver_message double(data: 'test 3')
              end
              subject.closing! 1005
            when 3
              expect(msg).to eq 'test 3'
              expect(subject).to receive(:websocket_read) do
                subject.closed! 1005, 'test'
              end
            end
          end

          expect(i).to eq 3
        end
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
      let(:ping_id) { 5 }
      before do
        subject.instance_variable_set('@ping_id', ping_id)
      end

      it "sends ping with next id" do
        expect(driver).to receive(:ping).with(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z/).and_return(true)

        subject.ping
      end

      it "sends ping with callback on pong" do
        ping_delay = nil

        subject.on_pong do |delay|
          ping_delay = delay
        end

        ping_id = nil
        ping_block = nil

        expect(driver).to receive(:ping) do |id, &block|
          ping_id = id
          ping_block = block

          true
        end

        subject.ping

        expect(ping_block).to_not be nil
        expect(ping_delay).to be nil

        ping_block.call

        expect(ping_delay).to_not be nil
        expect(ping_delay).to be > 0.0
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

    describe '#websocket_read' do
      it "reads from socket and passes it to locked driver for parsing" do
        expect(connection).to receive(:read).with(Integer, timeout: Float).and_return('asdf')
        expect(driver).to receive(:parse).with('asdf') do
          expect(mutex).to be_locked.and be_owned
        end

        subject.websocket_read
      end

      context 'while opening' do
        before do
          subject.opening!
        end

        it "reraises timeout with open state" do
          expect(subject).to receive(:socket_read).and_raise(Kontena::Websocket::TimeoutError, 'read timeout after 0.1s')

          expect{subject.websocket_read}.to raise_error(Kontena::Websocket::TimeoutError, 'read timeout after 0.1s while waiting 60.0s for open')
        end
      end

      context 'while open' do
        before do
          subject.opened!
        end

        it "sends ping on timeout" do
          expect(subject).to receive(:socket_read).and_raise(Kontena::Websocket::TimeoutError)
          expect(subject).to receive(:ping)

          subject.websocket_read
        end
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

    describe '#socket_connect' do
      it "calls connect_tcp an returns a Connection for the socket" do
        expect(subject).to receive(:connect_tcp).with(no_args).and_return(tcp_socket)

        connection = subject.socket_connect

        expect(connection.url).to eq url

        expect(tcp_socket).to receive(:write_nonblock).with('asdf').and_return(4)
        connection.write('asdf')
      end
    end
  end

  context 'for a wss:// url without verify' do
    let(:url) { 'wss://socket.example.com/' }
    subject { described_class.new(url, ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_NONE} ) }

    let(:tcp_socket) { instance_double(TCPSocket) }
    let(:ssl_socket) { instance_double(OpenSSL::SSL::SSLSocket) }

    before do
      allow(subject).to receive(:connect_tcp).and_return(tcp_socket)
    end

    it 'is ssl?' do
      expect(subject.ssl?).to be true
    end
    it 'is not ssl_verify?' do
      expect(subject.ssl_verify?).to be false
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

    describe '#socket_connect' do
      it "calls connect_ssl and returns a Connection for the socket" do
        expect(subject).to receive(:connect_ssl).with(no_args).and_return(ssl_socket)

        connection = subject.socket_connect

        expect(connection.url).to eq url

        expect(ssl_socket).to receive(:write_nonblock).with('asdf').and_return(4)
        connection.write('asdf')
      end
    end
  end

  context "for a wss:// URL with default verify_mode" do
    let(:url) { 'wss://socket.example.com/'}
    let(:options) { {} }
    subject { described_class.new(url, **options) }

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

    describe '#ssl_cert_store' do
      context "with a SSL_CERT_FILE= that does not exist" do
        before do
          ENV['SSL_CERT_FILE'] = './missing'
        end
        after do
          ENV['SSL_CERT_FILE'] = nil
        end

        subject { described_class.new('wss://socket.example.com') }

        it "raises an ArgumentError" do
          expect{subject.ssl_cert_store}.to raise_error(ArgumentError, "Failed adding cert store file: ./missing")
        end
      end

      context "with a ssl_params ca_path that does not exist" do
        subject {
          described_class.new('wss://socket.example.com',
            ssl_params: { ca_path: './missing/' },
          )
        }

        it "does not raise" do
          expect{subject.ssl_cert_store}.to_not raise_error
        end
      end
    end

    describe '#ssl_cert_store mock' do
      let(:ssl_cert_store) { instance_double(OpenSSL::X509::Store) }

      before do
        allow(OpenSSL::X509::Store).to receive(:new).and_return(ssl_cert_store)
      end

      it 'uses the default paths' do
        expect(ssl_cert_store).to receive(:set_default_paths)

        expect(subject.ssl_cert_store).to eq ssl_cert_store
      end

      context "with ssl_ca_file" do
        subject { described_class.new(url, ssl_params: { ca_file: '/etc/kontena-agent/ca.pem' } ) }

        it "adds the ca_file" do
          expect(ssl_cert_store).to receive(:add_file).with('/etc/kontena-agent/ca.pem')

          expect(subject.ssl_cert_store).to eq ssl_cert_store
        end
      end

      context "with ssl_ca_path" do
        subject { described_class.new(url, ssl_params: { ca_path: '/etc/kontena-agent/ca.d' } ) }

        it "configures ca_path" do
          expect(ssl_cert_store).to receive(:add_path).with('/etc/kontena-agent/ca.d')

          expect(subject.ssl_cert_store).to eq ssl_cert_store
        end
      end

      context "with SSL_CERT_FILE=" do
        before do
          ENV['SSL_CERT_FILE'] = '/etc/kontena-agent/ca.pem'
        end
        after do
          ENV['SSL_CERT_FILE'] = nil
        end

        it "adds the ca_file" do
          expect(ssl_cert_store).to receive(:add_file).with('/etc/kontena-agent/ca.pem')

          expect(subject.ssl_cert_store).to eq ssl_cert_store
        end
      end

      context "with SSL_CERT_PATH=" do
        before do
          ENV['SSL_CERT_PATH'] = '/etc/kontena-agent/ca.d'
        end
        after do
          ENV['SSL_CERT_PATH'] = nil
        end

        it "adds the ca_file" do
          expect(ssl_cert_store).to receive(:add_path).with('/etc/kontena-agent/ca.d')

          expect(subject.ssl_cert_store).to eq ssl_cert_store
        end
      end
    end

    describe '#ssl_verify_cert!' do
      let(:cert) { instance_double(OpenSSL::X509::Certificate) }
      let(:cert_chain) { [instance_double(OpenSSL::X509::Certificate)] }
      let(:cert_store) { instance_double(OpenSSL::X509::Store) }
      let(:cert_store_context) { instance_double(OpenSSL::X509::StoreContext) }

      before do
        allow(subject).to receive(:ssl_cert_store).and_return(cert_store)
        allow(OpenSSL::X509::StoreContext).to receive(:new).with(cert_store, cert, cert_chain).and_return(cert_store_context)
      end

      it "fails if no cert" do
        expect{subject.ssl_verify_cert!(nil, [])}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: No certificate')
      end

      it "fails if the certificate does not verify" do
        expect(cert_store_context).to receive(:verify).and_return(false)
        expect(cert_store_context).to receive(:error).and_return(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        expect(cert_store_context).to receive(:error_string).and_return('self signed certificate')

        expect{subject.ssl_verify_cert!(cert, cert_chain)}.to raise_error(Kontena::Websocket::SSLVerifyError, "certificate verify failed: self signed certificate")
      end

      it "fails if the certificate subject does not match" do
        expect(cert_store_context).to receive(:verify).and_return(true)
        expect(OpenSSL::SSL).to receive(:verify_certificate_identity).with(cert, 'socket.example.com').and_return(false)
        expect(cert).to receive(:subject).and_return(OpenSSL::X509::Name.parse '/CN=test')

        expect{subject.ssl_verify_cert!(cert, cert_chain)}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: Subject does not match hostname socket.example.com: /CN=test')
      end

      it "returns the peer cert if valid" do
        expect(cert_store_context).to receive(:verify).and_return(true)
        expect(OpenSSL::SSL).to receive(:verify_certificate_identity).with(cert, 'socket.example.com').and_return(true)

        expect{subject.ssl_verify_cert!(cert, cert_chain)}.to_not raise_error
      end

      context "with a ssl_hostname" do
        let(:options) { { ssl_hostname: 'test' }}

        it "uses the custom name for the identity check" do
          expect(cert_store_context).to receive(:verify).and_return(true)
          expect(OpenSSL::SSL).to receive(:verify_certificate_identity).with(cert, 'test').and_return(true)

          expect{subject.ssl_verify_cert!(cert, cert_chain)}.to_not raise_error
        end

        it "uses the custom name for the verify error" do
          expect(cert_store_context).to receive(:verify).and_return(true)
          expect(OpenSSL::SSL).to receive(:verify_certificate_identity).with(cert, 'test').and_return(false)
          expect(cert).to receive(:subject).and_return(OpenSSL::X509::Name.parse '/CN=not-test')

          expect{subject.ssl_verify_cert!(cert, cert_chain)}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: Subject does not match hostname test: /CN=not-test')
        end
      end
    end

    describe '#ssl_context' do
      let(:ssl_cert_store) { instance_double(OpenSSL::X509::Store) }

      before do
        allow(subject).to receive(:ssl_cert_store).and_return(ssl_cert_store)
      end

      it "configures verify_mode" do
        ssl_context = subject.ssl_context

        expect(ssl_context).to be_a OpenSSL::SSL::SSLContext
        expect(ssl_context.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
        expect(ssl_context.cert_store).to eq ssl_cert_store
      end
    end

    describe '#connect_ssl' do
      let(:ssl_cert) { instance_double(OpenSSL::X509::Certificate) }
      let(:ssl_cert_chain) { [instance_double(OpenSSL::X509::Certificate)] }

      before do
        expect(OpenSSL::SSL::SSLSocket).to receive(:new).with(tcp_socket, OpenSSL::SSL::SSLContext).and_return(ssl_socket)
      end

      it "connects with SNI, and verifies" do
        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect_nonblock)
        expect(ssl_socket).to receive(:peer_cert).and_return(ssl_cert)
        expect(ssl_socket).to receive(:peer_cert_chain).and_return(ssl_cert_chain)

        expect(subject).to receive(:ssl_verify_cert!).with(ssl_cert, ssl_cert_chain)

        expect(subject.connect_ssl).to eq ssl_socket
      end

      it "raises SSLVerifyError on cert identity failures" do
        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect_nonblock)
        expect(ssl_socket).to receive(:peer_cert).and_return(ssl_cert)
        expect(ssl_socket).to receive(:peer_cert_chain).and_return(ssl_cert_chain)

        expect(subject).to receive(:ssl_verify_cert!).with(ssl_cert, ssl_cert_chain).and_raise(Kontena::Websocket::SSLVerifyError.new(OpenSSL::X509::V_OK), 'Subject does not match hostname 127.0.0.1: /CN=localhost')

        expect{subject.connect_ssl}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: Subject does not match hostname 127.0.0.1: /CN=localhost')
      end

      it "raises SSLVerifyError on cert verify failures" do
        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect_nonblock).and_raise(OpenSSL::SSL::SSLError, 'SSL_connect returned=1 errno=0 state=error: certificate verify failed')
        expect(ssl_socket).to receive(:verify_result).and_return(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)

        expect(subject).to receive(:ssl_verify_error).with(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT).and_return(Kontena::Websocket::SSLVerifyError.new(OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, nil, nil, 'self signed certificate'))

        expect{subject.connect_ssl}.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: self signed certificate')
      end

      it "raises SSLConnectError on other ssl errors" do
        expect(ssl_socket).to receive(:sync_close=).with(true)
        expect(ssl_socket).to receive(:hostname=).with('socket.example.com')
        expect(ssl_socket).to receive(:connect_nonblock).and_raise(OpenSSL::SSL::SSLError, 'SSL_connect returned=1 errno=0 state=error: asdfasdf')

        expect{subject.connect_ssl}.to raise_error(Kontena::Websocket::SSLConnectError, 'SSL_connect returned=1 errno=0 state=error: asdfasdf')
      end

      context 'with a ssl_hostname' do
        let(:options) { { ssl_hostname: 'test' }}

        it "connects and verifies using the custom name" do
          expect(ssl_socket).to receive(:sync_close=).with(true)
          expect(ssl_socket).to receive(:hostname=).with('test')
          expect(ssl_socket).to receive(:connect_nonblock)
          expect(ssl_socket).to receive(:peer_cert).and_return(ssl_cert)
          expect(ssl_socket).to receive(:peer_cert_chain).and_return(ssl_cert_chain)

          expect(subject).to receive(:ssl_verify_cert!).with(ssl_cert, ssl_cert_chain)

          expect(subject.connect_ssl).to eq ssl_socket
        end
      end
    end
  end

  describe '#self.connect' do
    subject { instance_double(described_class) }

    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client::Connection) }
    let(:driver) { instance_double(WebSocket::Driver::Client) }

    before do
      allow(described_class).to receive(:new).and_return(subject)
    end

    it "connects the client before yielding, and then disconnects" do
      expect(subject).to receive(:connect)
      expect(subject).to receive(:disconnect)
      expect{|block| described_class.connect('ws://socket.example.com', &block)}.to yield_with_args(subject)
    end

    it "connects the client before yielding, and then disconnects" do
      expect(subject).to receive(:connect)
      expect(subject).to receive(:disconnect)
      expect{|block| described_class.connect('ws://socket.example.com', &block)}.to yield_with_args(subject) do
        raise Kontena::Websocket::Error, 'test'
      end
    end

    it 'does not disconnect on close errors' do
      expect(subject).to receive(:connect).and_raise(Kontena::Websocket::ConnectError, 'failed to connect')
      expect(subject).to_not receive(:disconnect)

      expect{
        described_class.connect('ws://socket.example.com').to_not yield_control
      }.to raise_error(Kontena::Websocket::ConnectError)
    end
  end
end
