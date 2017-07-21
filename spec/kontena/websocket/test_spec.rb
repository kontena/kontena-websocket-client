require 'tempfile'
require 'kontena-websocket-client'

RSpec.describe Kontena::Websocket::Client do
  let(:logger) {
    Logger.new(STDERR)
  }
  before do
    Thread.abort_on_exception = true
  end

  let(:url) { nil }
  let(:options) { { }}
  let(:subject) { described_class.new(url, **options) }

  context "For a server that does not resolve" do
    let(:url) { 'ws://socket.example.com' }

    it 'raises' do
      expect{
        subject.connect
      }.to raise_error(Kontena::Websocket::ConnectError, 'getaddrinfo: Name or service not known')
    end
  end

  context "For a server that is ECONNREFUSED" do
    let(:url) { 'ws://127.0.0.1:1337' }

    it 'raises ECONNREFUSED' do
      opened = false

      expect{
        subject.connect
      }.to raise_error(Kontena::Websocket::ConnectError, 'Connection refused - connect(2) for 127.0.0.1:1337')

      expect(opened).to be false
    end
  end

  context "For a blackholed server" do
    let(:url) { 'ws://192.0.2.1:1337' }
    let(:options) { { connect_timeout: 0.1 }}

    it "raises a connection timeout error" do
      expect{
        subject.connect
      }.to raise_error(Kontena::Websocket::TimeoutError, 'Connect timeout after 0.1s')
    end
  end

  context "For a local server on a random port" do
    let(:tcp_server) do
      TCPServer.new('127.0.0.1', 0)
    end
    let(:port) do
      af, port, hostname, ip = tcp_server.addr
      port
    end

    before do
      tcp_server
      server_thread
    end
    after do
      server_thread.kill
    end

    let(:url) { "ws://127.0.0.1:#{port}" }
    let(:options) { { open_timeout: 0.5 }}

    context "that immediately closes the connection" do
      let(:server_thread) do
        Thread.new do
          loop do
            client = tcp_server.accept
            client.readpartial(1024)
            client.close
          end
        end
      end

      it 'raises a EOF error' do
        expect{
          subject.connect
        }.to raise_error(Kontena::Websocket::EOFError, 'connection closed with code 1006: Server closed connection without sending close frame')
      end
    end

    context "that hangs after accepting the connection" do
      let(:server_thread) do
        Thread.new do
          loop do
            client = tcp_server.accept
            begin
              logger.debug "accepted #{client}, sleeping..."
              sleep 1.0
            ensure
              client.close
            end
          end
        end
      end

      it 'raises an open timeout' do
        expect{
          subject.connect
        }.to raise_error(Kontena::Websocket::TimeoutError, /read timeout after 0.\d+s while waiting 0.5s for open/)
      end
    end

    context "that stalls with infinite HTTP headers after accepting the connection" do
      let(:server_thread) do
        Thread.new do
          loop do
            client = tcp_server.accept
            begin
              logger.debug "accepted #{client}, reading..."
              client.readpartial(1024)
              logger.debug "read #{client}, writing out slow response..."

              client.write([
                "HTTP/1.1 101 Switching Protocols",
                "Upgrade: websocket",
                "Connection: upgrade",
              ].join("\r\n"))

              begin
                loop do
                  client.write("X-Foo: bar\r\n")
                  Thread.pass
                end
              rescue Errno::ECONNRESET => exc
                # expected
                logger.debug "server write error: #{exc}"
              end
            ensure
              client.close
            end
          end
        end
      end

      it 'raises an open timeout' do
        expect{
          subject.connect
        }.to raise_error(Kontena::Websocket::TimeoutError, /read (deadline expired|timeout after 0.\d+s) while waiting 0.5s for open/)
      end
    end

    context "that returns a HTTP 404 error" do
      let(:server_thread) do
        Thread.new do
          loop do
            client = tcp_server.accept
            client.readpartial(1024)
            client.write([
              "HTTP/1.1 404 Not Found",
              "Server: test",
              "Connection: close",
              "",
              "",
            ].join("\r\n"))
            #client.close
          end
        end
      end

      it 'raises a protocol error' do
        expect{
          subject.connect
        }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 404')
      end
    end

    context "with an random SSL cert" do
      let(:ssl_subject) do
        OpenSSL::X509::Name.parse "/CN=localhost"
      end
      let(:ssl_key) do
        ssl_key = OpenSSL::PKey::RSA.new(1024)
      end
      let(:ssl_cert) do
        key = ssl_key

        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 2
        cert.subject = ssl_subject
        cert.issuer = cert.subject # self-signe
        cert.public_key = key.public_key
        cert.not_before = Time.now - 60.0
        cert.not_after = Time.now + 60.0 # +/- 1 minute validity

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert

        cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
        cert.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
        cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
        cert.sign(key, OpenSSL::Digest::SHA256.new)
        cert
      end
      let(:ssl_context) do
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.cert = ssl_cert
        ssl_context.key = ssl_key
        ssl_context
      end
      let(:ssl_server) do
        logger.debug "listen ssl_cert=#{ssl_context.cert}"

        OpenSSL::SSL::SSLServer.new(tcp_server, ssl_context)
      end
      let(:server_thread) do
        # need to generate the ssl_cert first in the main thread to ensure that server and client get the same cert
        ssl_server = self.ssl_server

        Thread.new do
          loop do
            begin
              client = ssl_server.accept
              client.readpartial(1024)
              client.write([
                "HTTP/1.1 501 Not Implemented",
                "Server: test",
                "Connection: close",
                "",
                "",
              ].join("\r\n"))
              client.close
            rescue => exc
              logger.warn exc
            end
          end
        end
      end

      let(:url) { "wss://localhost:#{port}" }
      let(:ssl_params) { {} }
      let(:ssl_hostname) { nil }
      let(:options) { { ssl_params: ssl_params, ssl_hostname: ssl_hostname } }

      subject { described_class.new(url, **options) }

      context "without ssl verify" do
        let(:ssl_params) { { verify_mode: OpenSSL::SSL::VERIFY_NONE } }

        it 'is able to connect' do
          expect{
            subject.connect
          }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 501')
        end
      end

      context "with default ssl verify" do
        it 'raises a SSL verify error about a self-signed cert' do
          expect{
            subject.connect
          }.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: self signed certificate') do |error|

          expect(error.cert).to be nil
        end
      end

      context "with default verify and the cert configured as a CA cert" do
        let(:cert_file) do
          cert_file = Tempfile.new('kontena-websocket-ssl-cert')
          cert_file.print ssl_cert.to_pem
          cert_file.close
          cert_file
        end

        let(:ssl_params) { {
            verify_mode: OpenSSL::SSL::VERIFY_PEER,
            ca_file: cert_file.path,
        } }

        before do
          cert_file
        end

        after do
          cert_file.unlink
        end

        it 'is able to connect' do
          expect{
            subject.connect
          }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 501')
        end

        context 'with the wrong hostname' do
          let(:url) { "wss://127.0.0.1:#{port}" }

          it 'raises a SSL verify error about a self-signed cert' do
            expect{
              subject.connect
            }.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: Subject does not match hostname 127.0.0.1: /CN=localhost')
          end
        end

        context 'with a custom CN' do
          let(:ssl_hostname) do
            'Test'
          end
          let(:ssl_subject) do
            OpenSSL::X509::Name.parse "/C=FI/O=Test/OU=Test/CN=Test" # used by the cli Kontena::Machine::CertHelper
          end

          it 'is able to connect' do
            expect{
              subject.connect
            }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 501')
          end
        end
      end
    end
  end # XXX

    context 'that is a websocket server' do
      let(:server_thread) do
        Thread.new do
          loop do
            socket = tcp_server.accept

            begin
              driver = WebSocket::Driver.server(socket)
              driver.on :connect do |event|
                if WebSocket::Driver.websocket? driver.env
                  logger.info("websocket server connect: #{event}")
                  driver.start
                else
                  socket.write([
                    "HTTP/1.1 501 Not Implemented",
                    "Server: test",
                    "Connection: close",
                    "",
                    "",
                  ].join("\r\n"))
                  socket.close
                  return
                end
              end

              # echo
              driver.on :open do |event|
                logger.info("websocket server open: #{event}")
              end
              driver.on :error do |event|
                logger.info("websocket server error: #{event}")
                raise event
              end
              driver.on :message do |event|
                case event.data
                when 'sleep'
                  logger.info("websocket server: sleep 1.0")

                  sleep 1.0

                when 'close'
                  logger.info("websocket server: close 4000")

                  driver.close('test', 4000)

                else
                  logger.info("websocket server echo: #{event.data[0..16]}...")

                  driver.text(event.data)
                end
              end
              driver.on :close do |event|
                logger.info("websocket server close: #{event}")
              end

              loop do
                data = socket.readpartial(1024)
                driver.parse(data)
              end
            rescue => exc
              logger.warn exc
            ensure
              socket.close
            end
          end
        end
      end

      let(:ping_interval) { 10.0 }
      let(:options) {{
        connect_timeout: 1.0,
        open_timeout: 1.0,
        ping_interval: ping_interval,
        ping_timeout: 0.13,
        close_timeout: 0.11,
        write_timeout: 0.12,
      }}

      it 'is able to connect, exchange messages and close the connection' do
        opened = 0
        messages = []

        expect{
          described_class.connect(url, **options) do |subject|
            logger.info("websocket client open")
            opened += 1

            subject.send('Hello World!')
            subject.close

            subject.read do |message|
              messages << message
            end
          end
        }.to_not raise_error

        expect(opened).to eq 1
        expect(messages).to eq ['Hello World!']
      end

      it 'raises CloseError when server closes' do
        described_class.connect(url, **options) do |subject|
          subject.send('close')

          expect{subject.read}.to raise_error(Kontena::Websocket::CloseError, 'connection closed with code 4000: test')
        end
      end

      context "with a full send buffer" do
        it 'raises write timeout if the server blocks' do
          expect{
            described_class.connect(url, **options) do |subject|
              # XXX: kill thread?
              Thread.new do
                loop do
                  subject.send('spam' * 1024 * 8) # ~8KB
                end
              end

              # block the server for 1.0s, enough for the sender_thread to fill the socket read+write buffers
              subject.send('sleep')

              subject.read
            end
          }.to raise_error(Kontena::Websocket::TimeoutError, 'write timeout after 0.12s')
        end
      end

      it 'raises close timeout if the server blocks' do
        expect{
          described_class.connect(url, **options) do |subject|
            # block the server for 1.0s, enough for the sender_thread to fill the socket read+write buffers
            subject.send('sleep')
            subject.close

            subject.read
          end
        }.to raise_error(Kontena::Websocket::TimeoutError, /read timeout after 0.\d+s while waiting 0.11s for close/)
      end

      context 'with a short ping interval' do
        let(:ping_interval) { 0.2 }

        pending 'sees ping-pong delay' do
          ping_delay = nil

          described_class.connect(url, **options) do |subject|
            subject.on_pong do |delay|
              ping_delay = delay
              subject.close # XXX
            end

            # wait for ping
            subject.read
          end

          expect(ping_delay).to be > 0.0
        end

        it 'raises ping timeout if the server blocks' do
          expect{
            described_class.connect(url, **options) do |subject|
              # block the server for 1.0s, enough for the sender_thread to fill the socket read+write buffers
              subject.send('sleep')

              subject.read
            end
          }.to raise_error(Kontena::Websocket::TimeoutError, /read timeout after 0.\d+s while waiting 0.13s for pong/)
        end
      end
    end
  end
end
