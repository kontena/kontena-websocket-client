require 'kontena-websocket-client'

describe Kontena::Websocket::Client do
  let(:logger) {
    Logger.new(STDERR)
  }
  context "For a server that is ECONNREFUSED" do
    subject { described_class.new('ws://127.0.0.1:1337') }

    it 'raises ECONNREFUSED' do
      opened = false

      expect{
        subject.run do
          opened = true
        end
      }.to raise_error(Errno::ECONNREFUSED, 'Connection refused - connect(2) for "127.0.0.1" port 1337')

      expect(opened).to be false
    end
  end

  context "For a local server" do
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

    subject { described_class.new("ws://127.0.0.1:#{port}") }

    context "that immediately closes the connection" do
      let(:server_thread) do
        Thread.new do
          loop do
            client = tcp_server.accept
            client.close
          end
        end
      end

      it 'raises a EOF error' do
        expect{
          subject.run
        }.to raise_error(Kontena::Websocket::EOFError, 'Connection closed with code 1006: EOF')
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
          subject.run
        }.to raise_error(WebSocket::Driver::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 404')
      end
    end

    context "with an random SSL cert" do
      let(:ssl_cn) do
        'test'
      end
      let(:ssl_subject) do
        OpenSSL::X509::Name.parse "/CN=#{ssl_cn}"
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
        cert.not_after = cert.not_before + 60.0 # +/- 1 minute validity

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
        OpenSSL::SSL::SSLServer.new(tcp_server, ssl_context)
      end
      let(:server_thread) do
        Thread.new do
          loop do
            begin
              client = ssl_server.accept
              client.readpartial(1024)
              client.close
            rescue => exc
              logger.warn exc
            end
          end
        end
      end

      context "with ssl verify" do
        subject { described_class.new("wss://127.0.0.1:#{port}", ssl_verify: true) }

        it 'raises a SSL error' do
          expect{
            subject.run
          }.to raise_error(OpenSSL::SSL::SSLError, 'SSL_connect returned=1 errno=0 state=error: certificate verify failed')
        end
      end
    end
  end
end
