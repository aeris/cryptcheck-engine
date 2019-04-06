module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe SupportedGroup do
					let!(:socket) { MockSocket.new }

					let!(:packet) { '0008 001d 0017 0018 0019' }
					let!(:groups) { %i[x25519 secp256r1 secp384r1 secp521r1] }

					describe '::read' do
						it 'must read record' do
							socket.init packet
							extension = SupportedGroup.read socket
							expect(extension).to be_a SupportedGroup
							expect(extension.groups).to contain_exactly *groups
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = SupportedGroup.new groups
							extension.write socket
							expect(socket.content).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
