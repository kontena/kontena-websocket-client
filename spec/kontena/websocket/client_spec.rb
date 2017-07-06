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
      expect(subject.host).to eq 'socket.example.com'
      expect(subject.port).to eq 80
    end

    it "parses a wss:// URL" do
      subject = described_class.new('wss://socket.example.com')

      expect(subject.url).to eq 'wss://socket.example.com'
      expect(subject.scheme).to eq 'wss'
      expect(subject.ssl?).to be true
      expect(subject.host).to eq 'socket.example.com'
      expect(subject.port).to eq 443
    end

    it "parses a ws:// URL with a port" do
      subject = described_class.new('ws://socket.example.com:9292')

      expect(subject.url).to eq 'ws://socket.example.com:9292'
      expect(subject.scheme).to eq 'ws'
      expect(subject.ssl?).to be false
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

  context "with a connected driver" do
    let(:socket) { instance_double(TCPSocket) }
    let(:connection) { instance_double(Kontena::Websocket::Client) }
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
        expect(driver).to receive(:close).with(1000, nil).and_return(true)

        subject.close
      end

      it "closes with code and reason" do
        expect(driver).to receive(:close).with(4020, "nope").and_return(true)

        subject.close(4020, "nope")
      end

      it "fails if driver returns false" do
        expect(driver).to receive(:close).and_return(false)

        expect{subject.close}.to raise_error(RuntimeError)
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

        expect{subject.ssl_cert!}.to raise_error(OpenSSL::SSL::SSLError, "certificate verify failed: V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT")
      end

      it "returns post_connection_check" do
        expect(socket).to receive(:verify_result).and_return(OpenSSL::X509::V_OK)
        expect(socket).to receive(:post_connection_check).and_raise(OpenSSL::SSL::SSLError, 'hostname "192.168.66.1" does not match the server certificate')

        expect{subject.ssl_cert!}.to raise_error(OpenSSL::SSL::SSLError, 'hostname "192.168.66.1" does not match the server certificate')
      end

      it "returns the peer cert if valid" do
        expect(socket).to receive(:verify_result).and_return(OpenSSL::X509::V_OK)
        expect(socket).to receive(:post_connection_check).with('socket.example.com')
        expect(socket).to receive(:peer_cert).and_return(cert)

        expect(subject.ssl_cert!).to eq cert
      end
    end
  end

  context 'for a ws:// url' do
    let(:url) { 'ws://socket.example.com/'}
    subject { described_class.new(url) }

    let(:tcp_socket) { instance_double(TCPSocket) }

    describe '#connect_tcp' do
      it "connects using the right host and port" do
        expect(TCPSocket).to receive(:new).with('socket.example.com', 80).and_return(tcp_socket)

        socket = subject.connect_tcp

        expect(socket).to eq tcp_socket
      end
    end

    describe '#connect' do
      it "calls connect_tcp" do
        expect(subject).to receive(:connect_tcp).with(no_args).and_return(tcp_socket)

        connection = subject.connect

        expect(connection.url).to eq url

        expect(tcp_socket).to receive(:write).with('asdf')
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
        expect(ssl_socket).to receive(:connect)
        expect(ssl_socket).to_not receive(:post_connection_check)

        expect(subject.connect_ssl).to eq ssl_socket
      end
    end

    describe '#connect' do
      it "calls connect_ssl" do
        expect(subject).to receive(:connect_ssl).with(no_args).and_return(ssl_socket)

        connection = subject.connect

        expect(connection.url).to eq url

        expect(ssl_socket).to receive(:write).with('asdf')
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
end
