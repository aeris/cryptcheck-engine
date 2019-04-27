module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe RenegotiationInfo do
					let!(:io) { MockIO.new }

					let!(:packet) { '00' }

					describe '::read' do
						it 'must read record' do
							io.init packet
							read, extension = klass.read io
							expect(read).to eq 1
							expect(extension).to be_a RenegotiationInfo
							expect(extension.verify_data).to eq nil
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = klass.build
							written   = extension.write io
							expect(written).to eq 1
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
