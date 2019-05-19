module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe HelloRequest do
				let!(:io) { MockIO.new }

				describe '::read' do
					it 'must read record' do
						io.init ''
						record = klass.read io
						expect(io).to be_read 0
						expect(record).to be_a HelloRequest
					end
				end

				describe '#write' do
					it 'must write record' do
						record = klass.new
						record.write io
						expect(io).to be_hex_written ''
					end
				end
			end
		end
	end
end
