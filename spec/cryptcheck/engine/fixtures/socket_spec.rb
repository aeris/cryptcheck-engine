RSpec.describe Socket do
  describe '#connect_timeout' do
    context 'without server problem' do
      it 'connect' do
        echo_server do |server|
          addr   = server.addr
          addr   = Socket.pack_sockaddr_in addr[1], addr[2]
          socket = klass.new :INET, :STREAM
          socket.connect addr, timeout: 0.1
          socket.puts 'foo'
          msg = socket.readline.chomp
          expect(msg).to eq 'foo'
          socket.close
        end
      end
    end

    context 'with missing server' do
      it 'raise connection refused exception' do
        addr   = Socket.pack_sockaddr_in 65535, '127.0.0.1'
        socket = klass.new :INET, :STREAM
        expect { socket.connect addr, timeout: 0.1 }.to raise_error Errno::ECONNREFUSED
      end

      it 'raise timeout exception' do
        addr   = Socket.pack_sockaddr_in 65535, '203.0.113.0'
        socket = klass.new :INET, :STREAM
        expect { socket.connect addr, timeout: 0.1 }.to raise_error Errno::ETIMEDOUT
      end
    end
  end
end
