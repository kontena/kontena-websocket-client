require 'kontena-websocket-client'

describe Kontena::Websocket::Client do
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
    let(:server) do
      TCPServer.new('127.0.0.1', 0)
    end
    let(:port) do
      af, port, hostname, ip = server.addr
      port
    end

    before do
      server
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
            client = server.accept
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
            client = server.accept
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
  end
end
