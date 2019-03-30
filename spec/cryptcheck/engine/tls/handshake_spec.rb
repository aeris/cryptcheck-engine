module Cryptcheck::Engine
	module Tls
		RSpec.describe Handshake do
			let!(:socket) { MockSocket.new }

			describe '::read' do
				it 'must read record' do
					socket.init '00 000000'
					handshake = Handshake.read socket
					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end

				it 'must reject unknown record' do
					socket.init 'FF 000000'
					expect { RecordHeader.read socket }.to raise_error ProtocolError, 'Unknown content type 0xff'
				end
			end

			describe '#write' do
				it 'must write record' do
					record    = Handshake::HelloRequest.new
					handshake = Handshake.new record
					handshake.write socket
					expect(socket.content).to eq_hex '00 000000'
				end
			end
		end
	end
end
