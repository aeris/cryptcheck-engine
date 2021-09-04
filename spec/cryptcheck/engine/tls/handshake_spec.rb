module Cryptcheck::Engine
  module Tls
    RSpec.describe Handshake do
      let!(:io) { MockIO.new }

      describe '::read' do
        it 'must read record' do
          io.init '00 000000'
          handshake = klass.read nil, io, nil
          expect(io).to be_read 4
          expect(handshake).to be_a Handshake
          expect(handshake.record).to be_a klass::HelloRequest
        end

        it 'must reject unknown record' do
          io.init 'FF 000000'
          expect { klass.read nil, io, nil }.to raise_error ProtocolError, 'Unknown handshake type 0xFF'
        end
      end

      describe '#write' do
        it 'must write record' do
          record    = klass::HelloRequest.new
          handshake = klass.new record
          handshake.write nil, io
          expect(io).to be_hex_written '00 000000'
        end
      end
    end
  end
end
