module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe HelloRequest do
				let!(:io) { MockIO.new }

				describe '::read' do
					it 'must read record' do
						io.init ''
						read, record = klass.read io
						expect(read).to eq 0
						expect(record).to be_a HelloRequest
					end
				end

				describe '#write' do
					it 'must write record' do
						record  = klass.new
						written = record.write io
						expect(written).to eq 0
						expect(io.string).to eq_hex ''
					end
				end
			end
		end
	end
end
