module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe ServerHelloDone do
				let!(:io) { MockIO.new }

				let!(:packet) { '' }

				describe '::read' do
					it 'must read record' do
						io.init packet
						record = klass.read io
						expect(io).to be_read 0
						expect(record).to be_a ServerHelloDone
					end
				end

				describe '#write' do
					it 'must write record' do
						record = klass.new
						record.write io
						expect(io).to be_hex_written packet
					end
				end
			end
		end
	end
end
