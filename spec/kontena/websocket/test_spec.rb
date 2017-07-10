require 'tempfile'
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
      }.to raise_error(Kontena::Websocket::ConnectError, 'Connection refused - connect(2) for "127.0.0.1" port 1337')

      expect(opened).to be false
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

    subject { described_class.new("ws://127.0.0.1:#{port}") }

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
        }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 404')
      end
    end

    context "with an random SSL cert" do
      let(:ssl_cn) do
        'localhost'
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
        # XXX: need to generate the ssl_cert first in the main thread to ensure that server and client get the same cert
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

      context "with ssl verify" do
        subject {
          described_class.new("wss://localhost:#{port}",
            ssl_verify: true,
          )
        }

        it 'raises a SSL verify error about a self-signed cert' do
          expect{
            subject.run
          }.to raise_error(Kontena::Websocket::SSLVerifyError, 'certificate verify failed: V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT')
        end
      end

      context "with the cert configured as a CA cert" do
        let(:cert_file) do
          cert_file = Tempfile.new('kontena-websocket-ssl-cert')
          cert_file.print ssl_cert.to_pem
          cert_file.close
          cert_file
        end

        subject {
          described_class.new("wss://localhost:#{port}",
            ssl_verify: true,
            ssl_ca_file: cert_file.path,
          )
        }

        before do
          cert_file
          subject
        end

        after do
          cert_file.unlink
        end

        it 'is able to connect' do
          expect{
            subject.run
          }.to raise_error(Kontena::Websocket::ProtocolError, 'Error during WebSocket handshake: Unexpected response code: 501')
        end

        context 'with the wrong hostname' do
          subject {
            described_class.new("wss://127.0.0.1:#{port}",
              ssl_verify: true,
              ssl_ca_file: cert_file.path,
            )
          }

          it 'raises a SSL verify error about a self-signed cert' do
            expect{
              subject.run
            }.to raise_error(Kontena::Websocket::SSLVerifyError, 'hostname "127.0.0.1" does not match the server certificate')
          end
        end
      end
    end

    context 'that is a websocket server' do
      let(:server_thread) do
        Thread.new do
          loop do
            begin
              socket = tcp_server.accept

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
                logger.info("websocket server message: #{event}")
                driver.text(event.data)
              end
              driver.on :close do |event|
                logger.info("websocket server close: #{event}")
                socket.close
              end

              loop do
                data = socket.readpartial(1024)
                driver.parse(data)
              end
            rescue => exc
              logger.warn exc
            end
          end
        end
      end

      it 'is able to connect, exchange messages and close the connection' do
        opened = 0
        messages = []

        expect{
          subject.listen do |message|
            messages << message
          end

          subject.run do
            logger.info("websocket client open")
            opened += 1

            subject.send('Hello World!')

            subject.close
          end
        }.to_not raise_error

        expect(opened).to eq 1
        expect(messages).to eq ['Hello World!']
      end
    end
  end
end
