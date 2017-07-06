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

  context "For a server that immediately closes the connection" do
    let(:server) do
      TCPServer.new('127.0.0.1', 0)
    end
    let(:port) do
      af, port, hostname, ip = server.addr
      port
    end
    let(:server_thread) do
      Thread.new do
        loop do
          client = server.accept
          client.close
        end
      end
    end

    before do
      server
      server_thread
    end

    after do
      server_thread.kill
    end

    subject { described_class.new("ws://127.0.0.1:#{port}") }

    it 'raises a EOF error' do
      opened = false

      expect{
        subject.run do
          opened = true
        end
      }.to raise_error(Kontena::Websocket::EOFError, 'Connection closed with code 1006: EOF')

      expect(opened).to be false
    end
  end
end
