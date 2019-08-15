module Cryptcheck::Engine
	module Tls
		RSpec.describe Tls do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read record' do
					io.init '16 0300 0004 00 000000'
					header, handshake = klass.read nil, io

					expect(io).to be_read 9

					expect(header.type).to eq Handshake
					expect(header.version).to eq :ssl_3_0
					expect(header.length).to eq 0x04

					expect(handshake).to be_a Handshake
					expect(handshake.record).to be_a Handshake::HelloRequest
				end

				it 'must raise alert' do
					io.init '15 0303 0002 010A'
					expect { klass.read nil, io }.to raise_error AlertError do |error|
						alert = error.alert
						expect(alert.level).to eq :warning
						expect(alert.description).to eq :unexpected_message
					end
				end
			end

			describe '#write' do
				it 'must write record' do
					handshake_record = Handshake::HelloRequest.new
					record           = Handshake.new handshake_record
					klass.write nil, io, :ssl_3_0, record
					expect(io).to be_hex_written '16 0300 0004 00 000000'
				end
			end
		end
	end
end
