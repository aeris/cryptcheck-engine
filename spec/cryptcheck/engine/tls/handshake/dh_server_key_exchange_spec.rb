module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe DhServerKeyExchange do
				let!(:io) { MockIO.new }

				let!(:p) {
					<<~HEREDOC
					    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74
					    020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437
					    4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed
					    ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05
					    98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb
					    9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b
					    e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718
					    3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
					HEREDOC
				}
				let!(:g) { '02' }
				let!(:ys) {
					<<~HEREDOC
					    d76d2b7ca4c071d840459d62a6862611f9d3fb96953d7211b4a4cb74839f637e
					    ed3b5afcc626b30c6c80a7adc3dc3b4f93cbf8ee30b26313c924758f0aab3097
					    c76be34b0137761cd736688af56fe57094b92c874677b009c3268c7b3ea4e864
					    dd0d65beb822e0a74f58cf763deff95f8a5ca87a0d417c2a461b8aee9a8434f2
					    7c1fba398f9ac238a4c958328b336729c754d00aa0d3a91831b1b6323aa6ad66
					    57028d8895509150f8a40f5540eed41cfa3cdd867812496c26107c331d056454
					    fe6a305578afd4041fe8ab0de0dd6c19289484a2aa9e5f6f2b6df7f674866fd0
					    aa09d96d4507ff88a18260cc788ed503113de70cbde9bfaca47e8ccded2a231c
					HEREDOC
				}
				let!(:signature) {
					<<~HEREDOC
					    6e5d3443a19a13b962fa2dd297665f864683a3fce3ad5d081e2d2f16af9d4e4f
					    1765c80e34970ab9ab60f00db0f3863e14dea99ceh316155e41bce2fd05d80e81
					    f2f515b468bd8a892fd86629c60228290575fac898dca9d875c711068c56a9d0
					    7b4526012f8b36e8f44d999875f8ee6eada3e368b014762ef6d5eeed30932570
					    21cb55d8cfa3054cc176841ae3c9e2f61b36ddd42fe754a5acbeceeec19b8815
					    1aa6dc1f3f270402d15a26d1dbe8938cda5a3652b5f497eb16796addc5618002
					    82adcf601b9404c15b32f8fbf2bf99b2156bde082074f362e3c26f5c31d5a4f1
					    bbc65c838e26d8c44fa283c18e4e0bc366bb8bdb15c0c40bf7cc600c9d4d6ca6
					HEREDOC
				}
				let!(:anonymous_packet) {
					<<~HEREDOC
					    0100 #{p}
					    0001 #{g}
					    0100 #{ys}
					HEREDOC
				}
				let!(:packet) {
					<<~HEREDOC
					    #{anonymous_packet}
					    0401 0100 #{signature}
					HEREDOC
				}

				describe '::read' do
					context 'when anonymous' do
						it 'must read record without signature' do
							io.init anonymous_packet
							read, record = klass.read io, true
							expect(read).to eq 519
							expect(record).to be_a DhServerKeyExchange
							expect(record.p).to eq_hex p
							expect(record.g).to eq_hex g
							expect(record.ys).to eq_hex ys
							expect(record.signature).to be_nil
						end
					end

					context 'when authenticated' do
						it 'must read record with a signature' do
							io.init packet
							read, record = klass.read io
							expect(read).to eq 779
							expect(record).to be_a DhServerKeyExchange
							expect(record.p).to eq_hex p
							expect(record.g).to eq_hex g
							expect(record.ys).to eq_hex ys
							sign = record.signature
							expect(sign).to be_a Signature
							expect(sign.scheme).to eq :rsa_pkcs1_sha256
							expect(sign.signature).to eq_hex signature
						end
					end
				end

				describe '#write' do
					context 'when anonymous' do
						it 'must write record without signature' do
							record  = klass.new p.from_hex, g.from_hex, ys.from_hex
							written = record.write io
							expect(written).to eq 519
							expect(io.string).to eq_hex anonymous_packet
						end
					end

					context 'when authenticated' do
						it 'must write record with signature' do
							sign    = Signature.new :rsa_pkcs1_sha256, signature.from_hex
							record  = klass.new p.from_hex, g.from_hex, ys.from_hex, sign
							written = record.write io
							expect(written).to eq 779
							expect(io.string).to eq_hex packet
						end
					end
				end
			end
		end
	end
end
