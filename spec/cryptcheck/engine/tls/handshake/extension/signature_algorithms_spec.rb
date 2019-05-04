module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				RSpec.describe SignatureAlgorithms do
					let!(:io) { MockIO.new }

					let!(:packet) { '0016 0403 0503 0603 0804 0805 0806 0401 0501 0601 0203 0201' }
					let!(:schemes) { %i[
						ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512
						rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512
						rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512
						ecdsa_sha1
						rsa_pkcs1_sha1
					] }

					describe '::read' do
						it 'must read record' do
							io.init packet
							read, extension = klass.read io
							expect(read).to eq 24
							expect(extension).to be_a SignatureAlgorithms
							expect(extension.schemes).to eq schemes
						end
					end

					describe ' #write' do
						it 'must write record' do
							extension = klass.new schemes
							written   = extension.write io
							expect(written).to eq 24
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
