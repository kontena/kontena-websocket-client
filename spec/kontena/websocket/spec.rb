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
end
