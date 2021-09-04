module Cryptcheck::Engine
  module Tls
    class Handshake
      RSpec.describe EncryptedPreMasterKeySecret do
        let!(:io) { MockIO.new }

        let!(:encrypted_pre_master_secret) {
          <<~HEREDOC
            43920fbe26e830210f56532b66d987b9fb6b4dceea577eb51d18a1c5d73231d0
            ebfc0cc2a7c7457e455b5b298de80f56e5feb240da00c92c9d4516c94b684699
            e5aa3543f2a2f832f255cdcbe590552c3891e5af9b61980e2ef7082fae3490c2
            c69dc363a8b29ceed9489a7fa85108601c5656973bd22dda9fc2b31344e26e9f
            9380f92fef4216805c5ef35a6ef20258ee6993818cd53550a8570f1b5c58e186
            3ad93a35326516a49f79f0da58422a5708d5fd13879194a71b2a519d4ef05352
            d4ec24ef2021be99f3207adfeb2540751c79ba4c24ed3b8142db602e0a5b93e9
            9132aa93244a3bd4d5e98ccd506796b54cd7810c08e24f18c45cc454eaf3412d
          HEREDOC
        }
        let!(:packet) { "0100 #{encrypted_pre_master_secret}" }

        describe '::read' do
          it 'must read record' do
            io.init packet
            record = klass.read nil, io
            expect(io).to be_read 258
            expect(record).to be_a EncryptedPreMasterKeySecret
            expect(record.encrypted_pre_master_secret).to eq_hex encrypted_pre_master_secret
          end
        end

        describe '#write' do
          it 'must write record' do
            record = EncryptedPreMasterKeySecret.new encrypted_pre_master_secret.from_hex
            record.write nil, io
            expect(io).to be_hex_written packet
          end
        end
      end
    end
  end
end
