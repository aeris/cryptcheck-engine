module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe HelloRequest do
				let!(:socket) { MockSocket.new }

				describe '::read' do
					it 'must read record' do
						socket.init ''
						record = HelloRequest.read socket
						expect(record).to be_a HelloRequest
					end
				end

				describe '#write' do
					it 'must write record' do
						record = HelloRequest.new
						record.write socket
						expect(socket.content).to eq "".b
					end
				end
			end
		end
	end
end
