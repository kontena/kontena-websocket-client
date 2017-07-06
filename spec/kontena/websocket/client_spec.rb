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
end
