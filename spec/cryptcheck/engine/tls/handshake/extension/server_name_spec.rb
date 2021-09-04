module Cryptcheck::Engine
  module Tls
    class Handshake
      class Extension
        RSpec.describe ServerName do
          let!(:io) { MockIO.new }

          let!(:packet) { '0010 00 000d 6372797074636865636b2e6672' }
          let!(:names) { [{ type: :hostname, hostname: 'cryptcheck.fr' }] }

          describe '::read' do
            it 'must read record' do
              io.init packet
              extension = klass.read io
              expect(io).to be_read 18
              expect(extension).to be_a ServerName
              expect(extension.names).to eq names
            end
          end

          describe ' #write' do
            it 'must write record' do
              extension = klass.new names
              extension.write io
              expect(io).to be_hex_written packet
            end
          end
        end
      end
    end
  end
end
