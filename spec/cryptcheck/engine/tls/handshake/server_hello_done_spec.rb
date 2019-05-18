module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe ServerHelloDone do
				let!(:io) { MockIO.new }

				let!(:packet) { '' }

				describe '::read' do
					it 'must read record' do
						io.init packet
						read, record = klass.read io
						expect(read).to eq 0
						expect(record).to be_a ServerHelloDone
					end
				end

				describe '#write' do
					it 'must write record' do
						record  = klass.new
						written = record.write io
						expect(written).to eq 0
						expect(io.string).to eq_hex packet
					end
				end
			end
		end
	end
end
