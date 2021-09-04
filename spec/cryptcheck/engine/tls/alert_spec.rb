module Cryptcheck::Engine
  module Tls
    RSpec.describe Alert do
      let!(:io) { MockIO.new }

      describe '::read' do
        it 'must read record' do
          io.init '01 0A'
          alert = klass.read nil, io
          expect(io).to be_read 2
          expect(alert).to be_a Alert
          expect(alert.level).to eq :warning
          expect(alert.description).to eq :unexpected_message
        end

        it 'must reject unknown level' do
          io.init 'FF 0A'
          expect { klass.read nil, io }.to raise_error ProtocolError, 'Unknown alert level 0xFF'
        end

        it 'must reject unknown description' do
          io.init '01 FF'
          expect { klass.read nil, io }.to raise_error ProtocolError, 'Unknown alert description 0xFF'
        end
      end

      describe '#write' do
        it 'must write record' do
          alert = klass.new :warning, :unexpected_message
          alert.write nil, io
          expect(io).to be_hex_written '01 0A'
        end
      end
    end
  end
end
