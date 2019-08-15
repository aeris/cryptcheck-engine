module Cryptcheck::Engine
	module Tls
		RSpec.describe RecordHeader do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read header' do
					io.init '16 0300 8182'
					header = klass.read nil, io
					expect(io).to be_read 5
					expect(header.type).to eq Handshake
					expect(header.version).to eq :ssl_3_0
					expect(header.length).to eq 0x8182
				end

				it 'must reject invalid content type' do
					io.init 'FF 0300 8182'
					expect { klass.read nil, io }.to raise_error ProtocolError, 'Unknown content type 0xFF'
				end

				it 'must reject invalid version' do
					io.init '16 FFFF 8182'
					expect { klass.read nil, io }.to raise_error ProtocolError, 'Unknown version 0xFFFF'
				end
			end

			describe '#write' do
				it 'must write header' do
					header = klass.new Handshake, :ssl_3_0, 0x8182
					header.write nil, io
					expect(io).to be_hex_written '16 0300 8182'
				end
			end
		end
	end
end
