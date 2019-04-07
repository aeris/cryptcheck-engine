module Cryptcheck::Engine
	module Tls
		RSpec.describe Tls do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read record' do
					io.init '16 0300 0004 00 000000'
					read, header, handshake = Tls.read io

					expect(read).to be 9

					expect(header.type).to be Handshake
					expect(header.version).to be :ssl_3_0
					expect(header.length).to be 0x04

					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end
			end

			describe '#write' do
				it 'must write record' do
					handshake_record = Handshake::HelloRequest.new
					record           = Handshake.new handshake_record
					written          = Tls.write io, :ssl_3_0, record
					expect(written).to be 9
					expect(io.string).to eq_hex '16 0300 0004 00 000000'
				end
			end
		end
	end
end
