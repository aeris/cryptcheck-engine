module Cryptcheck::Engine
	module Tls
		RSpec.describe Tls do
			let!(:socket) { MockSocket.new }

			describe '::read' do
				it 'must read record' do
					socket.init "\x16\x03\x00\x00\x03\x00\x00\x00\x00".b
					header, handshake = Tls.read socket

					expect(header.type).to be Handshake
					expect(header.version).to be :ssl_3_0
					expect(header.length).to be 0x03

					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end
			end

			describe '#write' do
				it 'must write record' do
					handshake_record = Handshake::HelloRequest.new
					record           = Handshake.new handshake_record
					Tls.write socket, :ssl_3_0, record
					expect(socket.content).to eq "\x16\x03\x00\x00\x04\x00\x00\x00\x00".b
				end
				# end
				#
				# describe '#write' do
				# 	it 'must write record' do
				# 		socket.init "\x16\x03\x00\x00\x03\x01\x02\x03".b
				# 		record = Handshake::HelloRequest.new
				# 		Tls.write socket, :ssl_3_0, record
				# 		header = RecordHeader.new Handshake::Record, 0x03
				# 		# record = Handshake::Record.new "\x01\x02\x03".b
				# 		# record.write socket
				# 	end
				# end
			end
		end
	end
end
