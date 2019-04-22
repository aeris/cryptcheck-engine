module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe SupportedGroups do
					let!(:io) { MockIO.new }

					let!(:packet) { '0008 001d 0017 0018 0019' }
					let!(:groups) { %i[x25519 secp256r1 secp384r1 secp521r1] }

					describe '::read' do
						it 'must read record' do
							io.init packet
							read, extension = SupportedGroups.read io
							expect(read).to eq 10
							expect(extension).to be_a SupportedGroups
							expect(extension.groups).to eq groups
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = SupportedGroups.new groups
							written   = extension.write io
							expect(written).to eq 10
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
