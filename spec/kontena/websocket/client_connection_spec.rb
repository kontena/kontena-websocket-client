require 'kontena-websocket-client'

RSpec.describe Kontena::Websocket::Client::Connection do
  let(:uri) { URI.parse('ws://socket.example.com') }
  let(:socket) { instance_double(TCPSocket) }

  subject { described_class.new(uri, socket) }

  it 'has an url' do
    expect(subject.url).to eq 'ws://socket.example.com'
  end

  describe '#write' do
    it 'writes to the socket' do
      expect(socket).to receive(:write_nonblock).with('asdf').and_return(4)

      subject.write('asdf')
    end

    it 'writes a large string to the socket in multiple chunks' do
      expect(socket).to receive(:write_nonblock).with('asdf' * 16).and_return(4 * 8)
      expect(socket).to receive(:write_nonblock).with('asdf' * 8).and_return(4 * 4)
      expect(socket).to receive(:write_nonblock).with('asdf' * 4).and_return(4 * 4)

      subject.write('asdf' * 16)
    end

    it 'waits on write without a timeout' do
      expect(socket).to receive(:write_nonblock).with('asdf').and_raise(Class.new(Errno::ETIMEDOUT) do
        include IO::WaitWritable
      end)
      expect(subject).to receive(:wait_socket_writable!).with(socket, nil).and_return(socket)
      expect(socket).to receive(:write_nonblock).with('asdf').and_return(4)

      subject.write('asdf')
    end

    context 'with a write timeout' do
      subject { described_class.new(uri, socket, write_timeout: 1.0) }

      it 'waits on write without a timeout' do
        expect(socket).to receive(:write_nonblock).with('asdf').and_raise(Class.new(Errno::ETIMEDOUT) do
          include IO::WaitWritable
        end)
        expect(subject).to receive(:wait_socket_writable!).with(socket, 1.0).and_raise(Kontena::Websocket::TimeoutError, 'write timeout after 1.0s')

        expect{
          subject.write('asdf')
        }.to raise_error(Kontena::Websocket::TimeoutError, 'write timeout after 1.0s')
      end
    end
  end
end
