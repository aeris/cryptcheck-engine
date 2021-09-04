module Cryptcheck::Engine
  module Tls
    class Handshake
      RSpec.describe ClientEllipticCurveDiffieHellmanPublic do
        let!(:io) { MockIO.new }

        let!(:public_key) {
          <<~HEREDOC
            04143960688998b067b18674303472edc
            3f99c05ca0efc34a0a95cb7dda271cf6b
            d05350edcbdb056bf9e227bbb4adf6ba0
            9ddf363e742f8903f90bbbbd5fb2c46
          HEREDOC
        }
        let!(:packet) { "41 #{public_key}" }

        describe '::read' do
          it 'must read record' do
            io.init packet
            record = klass.read nil, io
            expect(io).to be_read 66
            expect(record).to be_a ClientEllipticCurveDiffieHellmanPublic
            expect(record.public_key).to eq_hex public_key
          end
        end

        describe '#write' do
          it 'must write record' do
            record = ClientEllipticCurveDiffieHellmanPublic.new public_key.from_hex
            record.write nil, io
            expect(io).to be_hex_written packet
          end
        end
      end
    end
  end
end
