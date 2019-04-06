module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe ServerName do
					let!(:socket) { MockSocket.new }

					let!(:packet) { '0010 00 000d 6372797074636865636b2e6672' }
					let!(:names) { [{ type: :hostname, hostname: 'cryptcheck.fr' }] }

					describe '::read' do
						it 'must read record' do
							socket.init packet
							extension = ServerName.read socket
							expect(extension).to be_a ServerName
							expect(extension.names).to contain_exactly *names
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = ServerName.new names
							extension.write socket
							expect(socket.content).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
