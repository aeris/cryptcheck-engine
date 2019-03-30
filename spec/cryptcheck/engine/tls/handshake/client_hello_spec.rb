module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe ClientHello do
				let!(:socket) { MockSocket.new }

				TIME     = Time.parse '2019-03-30 14:53:46 +0100'
				TIME_RAW = "\x5C\x9F\x74\xEA".b
				RANDOM   = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B" + "\x0C\xD\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B").b
				PACKET   = (TIME_RAW + RANDOM).b

				describe '::read' do
					it 'must read record' do
						socket.init PACKET
						record = ClientHello.read socket
						expect(record).to be_a ClientHello
						expect(record.time).to eq TIME
						expect(record.random).to eq RANDOM
					end
				end

				describe '#write' do
					it 'must write record' do
						record = ClientHello.new TIME, RANDOM
						record.write socket
						expect(socket.content).to eq PACKET
					end
				end
			end
		end
	end
end
