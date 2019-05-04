module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe EcdhServerKeyExchange do
				let!(:io) { MockIO.new }

				let!(:public_key) {
					<<~HEREDOC
						04dd86c16f8176849174554b5a44cbd50bd34ae6f40750315b6735dd8b6e7e96
						3fe7c3feee5a8ada4946404c7160b260d64425ff8ebbaec16c7f4e2dd0a71279
						68
					HEREDOC
				}
				let!(:signature) {
					<<~HEREDOC
						5bc8fd4e409adc226abee08dd12d9d27ce8542267544e7881b3446c3b17328fa
						43f82d3c575d57041466bdec7456eeafd35bb760ccb18ee2530e144134be5bbf
						dee2f8eaab39ab3a52bf841ace6c10862b24eca2c9261d53c45e30da41ddb1c1
						f087f89bc4dd7ba01abdbcede001e80403329bdb64191da052191cbaf18cb3f6
						884660d07a409002b5abff78bf8a050399b2c259c26594a549b6fb2d1cc20e0d
						fd147498165bb86c9a2af9091aef372783899667544b7cf9e4f7e7af2e68d140
						5b92c6c3384f58c86f414d8d1fca276267870cfe8c2c93062198bf4ec438205d
						caf93df3686809c0b0432f5c46f7fa2495f23ce6d28c74c08d1083721d519be2
					HEREDOC
				}
				let!(:packet) {
					<<~HEREDOC
						03 0017 41 #{public_key}
						0401 0100 #{signature}
					HEREDOC
				}

				describe '::read' do
					it 'must read record' do
						io.init packet
						read, record = klass.read io
						expect(read).to eq 329
						expect(record).to be_a EcdhServerKeyExchange
						expect(record.group).to eq :secp256r1
						expect(record.public_key).to eq_hex public_key
						sign = record.signature
						expect(sign).to be_a Signature
						expect(sign.scheme).to eq :rsa_pkcs1_sha256
						expect(sign.signature).to eq_hex signature
					end
				end

				describe '#write' do
					it 'must write record' do
						sign    = Signature.new :rsa_pkcs1_sha256, signature.from_hex
						record  = klass.new :secp256r1, public_key.from_hex, sign
						written = record.write io
						expect(written).to eq 329
						expect(io.string).to eq_hex packet
					end
				end
			end
		end
	end
end
