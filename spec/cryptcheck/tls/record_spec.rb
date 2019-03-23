module Cryptcheck::Engine
	module Tls
		RSpec.describe Record do
			let!(:socket) { Socket.new :INET, :STREAM }

			describe '#new' do
				it 'must detect length inconsistency' do
					header = RecordHeader.new :handshake, :ssl_3_0, 0x01
					expect { Record.new header, "\x01\x02" }.to raise_error Error, 'Inconsistency between header length (1) and data length (2)'
				end
			end

			describe '::read' do
				it 'must read record' do
					expect(socket).to receive(:recvmsg).with(1, timeout: nil).and_return("\x16".b).ordered
					expect(socket).to receive(:recvmsg).with(2, timeout: nil).and_return("\x03\x00".b).ordered
					expect(socket).to receive(:recvmsg).with(2, timeout: nil).and_return("\x00\x03".b).ordered
					expect(socket).to receive(:recvmsg).with(3, timeout: nil).and_return("\x01\x02\x03".b).ordered

					record = Record.read socket

					header = record.header
					expect(header.type).to be :handshake
					expect(header.version).to be :ssl_3_0
					expect(header.length).to be 0x03

					expect(record.data).to eq "\x01\x02\x03".b
				end
			end

			describe '#write' do
				it 'must write record' do
					expect(socket).to receive(:sendmsg).with("\x16".b, timeout: nil).ordered
					expect(socket).to receive(:sendmsg).with("\x03\x00".b, timeout: nil).ordered
					expect(socket).to receive(:sendmsg).with("\x00\x03".b, timeout: nil).ordered
					expect(socket).to receive(:sendmsg).with("\x01\x02\x03".b, timeout: nil).ordered

					header = RecordHeader.new :handshake, :ssl_3_0, 0x03
					record = Record.new header, "\x01\x02\x03".b
					record.write socket
				end
			end
		end
	end
end
