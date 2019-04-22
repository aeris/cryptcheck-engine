module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe SupportedVersions do
					let!(:io) { MockIO.new }

					let!(:packet) { '08 0304 0303 0302 0301' }
					let!(:versions) { %i[tls_1_3 tls_1_2 tls_1_1 tls_1_0] }

					describe '::read' do
						it 'must read record' do
							io.init packet
							read, extension = SupportedVersions.read io
							expect(read).to eq 9
							expect(extension).to be_a SupportedVersions
							expect(extension.versions).to eq versions
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = SupportedVersions.new versions
							written   = extension.write io
							expect(written).to eq 9
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
