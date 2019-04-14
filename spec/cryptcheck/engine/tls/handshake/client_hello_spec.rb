module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe ClientHello do
				let!(:io) { MockIO.new }

				let!(:packet) {
					<<~HEREDOC
					    0303
					    d2fd9f45420f2aee2f2066b1bf44f939a382ccf734277107412d091891aecbe4
					    20 2c29c80d4f5e8876a5c52bdc9bdfd811b43602f92d54c5cc0d3a435bec9a6549
					    0024
					    	1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c00a c009
					    	c013 c014 0033 0039 002f 0035 000a
					    01 00
					    018f
					    	0000 0011 0010 00 000d 6372797074636865636b2e6672
					    	0017 0000
					    	ff01 0001 00
					    	000a 000e 000c001d00170018001901000101
					    	000b 0002 0100
					    	0023 0000
					    	0010 000e 000c02683208687474702f312e31
					    	0005 0005 0100000000
					    	0033 006b 0069001d002017b1ca9773df23640849d7ecd64f3ca01434f1cf9e5e467828317bc7c92732090017004104c48534237482b446271ff73e148171bbe55bdd6d943607d226fbb30d4ee48ebff4a1f9764e4d4f51e427c1856f4ee6b0fa60e23d0c0349c3229da5a0ebbb70a6
					    	002b 0009 08 0304 0303 0302 0301
					    	000d 0018 0016 0403 0503 0603 0804 0805 0806 0401 0501 0601 0203 0201
					    	002d 0002 0101
					    	001c 0002 4001
					    	0015 0094 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
					HEREDOC
				}

				describe '::read' do
					it 'must read record' do
						io.init packet
						read, record = ClientHello.read io
						expect(read).to be 511
						expect(record).to be_a ClientHello
					end
				end

				describe '#write' do
					it 'must write record' do
						record  = ClientHello.build {
							version :tls_1_2
							random 'd2fd9f45420f2aee2f2066b1bf44f939a382ccf734277107412d091891aecbe4'.from_hex
							session '2c29c80d4f5e8876a5c52bdc9bdfd811b43602f92d54c5cc0d3a435bec9a6549'.from_hex
							cipher :TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
							cipher :TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
							cipher :TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
							cipher :TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
							cipher :TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
							cipher :TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
							extension Extension::ServerName.build 'cryptcheck.fr'
						}
						written = record.write io
						expect(written).to be 107
						expect(io.string).to eq_hex <<~HEREDOC
						    0303
						    d2fd9f45420f2aee2f2066b1bf44f939a382ccf734277107412d091891aecbe4
						    20 2c29c80d4f5e8876a5c52bdc9bdfd811b43602f92d54c5cc0d3a435bec9a6549
						    000c
						    	cca8 cca9 c02f c030 c02b c02c
						    01 00
						    0016
						    	0000 0012 0010 00 000d 6372797074636865636b2e6672
						HEREDOC
					end
				end
			end
		end
	end
end
