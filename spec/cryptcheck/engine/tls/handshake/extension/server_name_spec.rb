module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe ServerName do
					let!(:io) { MockIO.new }

					let!(:packet) { '0010 00 000d 6372797074636865636b2e6672' }
					let!(:names) { [{ type: :hostname, hostname: 'cryptcheck.fr' }] }

					describe '::read' do
						it 'must read record' do
							io.init packet
							read, extension = ServerName.read io
							expect(read).to be 18
							expect(extension).to be_a ServerName
							expect(extension.names).to contain_exactly *names
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = ServerName.new names
							written   = extension.write io
							expect(written).to be 18
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
