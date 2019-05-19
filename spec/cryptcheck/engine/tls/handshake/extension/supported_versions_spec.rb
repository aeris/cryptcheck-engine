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
							extension = klass.read io
							expect(io).to be_read 9
							expect(extension).to be_a SupportedVersions
							expect(extension.versions).to eq versions
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = klass.new versions
							extension.write io
							expect(io).to be_hex_written packet
						end
					end
				end
			end
		end
	end
end
