module Cryptcheck::Engine
	module Tls
		RSpec.describe RecordHeader do
			let!(:socket) { Socket.new :INET, :STREAM }

			describe '::read' do
				it 'must read header' do
					expect(socket).to receive(:recvmsg).with(1, timeout: nil).and_return("\x16".b).ordered
					expect(socket).to receive(:recvmsg).with(2, timeout: nil).and_return("\x03\x00".b).ordered
					expect(socket).to receive(:recvmsg).with(2, timeout: nil).and_return("\x81\x82".b).ordered

					header = RecordHeader.read socket
					expect(header.type).to be :handshake
					expect(header.version).to be :ssl_3_0
					expect(header.length).to be 0x8182
				end

				it 'must reject invalid content type' do
					allow(socket).to receive(:recvmsg).with(1, timeout: nil).and_return("\xff".b)
					expect { RecordHeader.read socket }.to raise_error ProtocolError, 'Unknown content type 0xff'
				end

				it 'must reject invalid version' do
					expect(socket).to receive(:recvmsg).with(1, timeout: nil).and_return("\x16".b).ordered
					expect(socket).to receive(:recvmsg).with(2, timeout: nil).and_return("\xff\xff".b).ordered
					expect { RecordHeader.read socket }.to raise_error ProtocolError, 'Unknown version 0xffff'
				end
			end

			describe '#write' do
				it 'must write header' do
					expect(socket).to receive(:sendmsg).with("\x16".b, timeout: nil).ordered
					expect(socket).to receive(:sendmsg).with("\x03\x00".b, timeout: nil).ordered
					expect(socket).to receive(:sendmsg).with("\x81\x82".b, timeout: nil).ordered


					header = RecordHeader.new :handshake, :ssl_3_0, 0x8182
					header.write socket
				end
			end
		end
	end
end
