module Cryptcheck::Engine
	module Tls
		RSpec.describe RecordHeader do
			let!(:socket) { MockSocket.new }

			describe '::read' do
				it 'must read header' do
					socket.init '16 0300 8182'
					header = RecordHeader.read socket
					expect(header.type).to be Handshake
					expect(header.version).to be :ssl_3_0
					expect(header.length).to be 0x8182
				end

				it 'must reject invalid content type' do
					socket.init 'FF 0300 8182'
					expect { RecordHeader.read socket }.to raise_error ProtocolError, 'Unknown content type 0xff'
				end

				it 'must reject invalid version' do
					socket.init '16 FFFF 8182'
					expect { RecordHeader.read socket }.to raise_error ProtocolError, 'Unknown version 0xffff'
				end
			end

			describe '#write' do
				it 'must write header' do
					header = RecordHeader.new Handshake, :ssl_3_0, 0x8182
					header.write socket
					expect(socket.content).to eq_hex '16 0300 8182'
				end
			end
		end
	end
end
