module Cryptcheck::Engine
	module Tls
		RSpec.describe Tls do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read record' do
					io.init '16 0300 0004 00 000000'
					read, header, handshake = Tls.read io

					expect(read).to eq 9

					expect(header.type).to eq Handshake
					expect(header.version).to eq :ssl_3_0
					expect(header.length).to eq 0x04

					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end
			end

			describe '#write' do
				it 'must write record' do
					handshake_record = Handshake::HelloRequest.new
					record           = Handshake.new handshake_record
					written          = Tls.write io, :ssl_3_0, record
					expect(written).to eq 9
					expect(io.string).to eq_hex '16 0300 0004 00 000000'
				end
			end
		end
	end
end
