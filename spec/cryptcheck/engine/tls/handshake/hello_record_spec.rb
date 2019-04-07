module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe HelloRequest do
				let!(:io) { MockIO.new }

				describe '::read' do
					it 'must read record' do
						io.init ''
						read, record = HelloRequest.read io
						expect(read).to be 0
						expect(record).to be_a HelloRequest
					end
				end

				describe '#write' do
					it 'must write record' do
						record  = HelloRequest.new
						written = record.write io
						expect(written).to be 0
						expect(io.string).to eq_hex ''
					end
				end
			end
		end
	end
end
