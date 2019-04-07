module Cryptcheck::Engine
	module Tls
		RSpec.describe Handshake do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read record' do
					io.init '00 000000'
					read, handshake = Handshake.read io
					expect(read).to be 4
					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end

				it 'must reject unknown record' do
					io.init 'FF 000000'
					expect { RecordHeader.read io }.to raise_error ProtocolError, 'Unknown content type 0xff'
				end
			end

			describe '#write' do
				it 'must write record' do
					record    = Handshake::HelloRequest.new
					handshake = Handshake.new record
					written = handshake.write io
					expect(written).to be 4
					expect(io.string).to eq_hex '00 000000'
				end
			end
		end
	end
end
