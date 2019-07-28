module Cryptcheck::Engine
	module Tls
		RSpec.describe ChangeCipherSpec do
			let!(:io) { MockIO.new }

			describe '::read' do
				it 'must read record' do
					io.init '01'
					change_cipher_spec = klass.read io
					expect(io).to be_read 1
					expect(change_cipher_spec).to be_a ChangeCipherSpec
				end

				it 'must reject unexpected payload' do
					io.init '02'
					expect { klass.read io }.to raise_error ProtocolError, 'Expect change cipher spec payload to be 0x01, got 0x02'
				end
			end

			describe '#write' do
				it 'must write record' do
					change_cipher_spec = klass.new
					change_cipher_spec.write io
					expect(io).to be_hex_written '01'
				end
			end
		end
	end
end
