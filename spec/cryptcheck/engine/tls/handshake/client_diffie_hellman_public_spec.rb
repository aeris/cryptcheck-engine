module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe ClientDiffieHellmanPublic do
				let!(:io) { MockIO.new }

				let!(:public_key) { '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254' }
				let!(:packet) { "0020 #{public_key}" }

				describe '::read' do
					it 'must read record' do
						io.init packet
						record = klass.read io
						expect(io).to be_read 34
						expect(record).to be_a ClientDiffieHellmanPublic
						expect(record.public_key).to eq_hex public_key
					end
				end

				describe '#write' do
					it 'must write record' do
						record = ClientDiffieHellmanPublic.new public_key.from_hex
						record.write io
						expect(io).to be_hex_written packet
					end
				end
			end
		end
	end
end
