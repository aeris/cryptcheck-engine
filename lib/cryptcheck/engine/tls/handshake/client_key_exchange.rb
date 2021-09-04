module Cryptcheck::Engine
  module Tls
    class Handshake
      class ClientKeyExchange
        ID = 0x10
      end

      class ClientEllipticCurveDiffieHellmanPublic < ClientKeyExchange
        def self.read(_, io)
          public_key = io.read_data :uint8
          self.new public_key
        end

        def write(_, io)
          io.write_data :uint8, @public_key
        end

        attr_reader :public_key

        def initialize(public_key)
          @public_key = public_key
        end
      end

      class ClientDiffieHellmanPublic < ClientKeyExchange
        def self.read(_, io)
          public_key = io.read_data :uint16
          self.new public_key
        end

        def write(_, io)
          io.write_data :uint16, @public_key
        end

        attr_reader :public_key

        def initialize(public_key)
          @public_key = public_key
        end
      end

      class EncryptedPreMasterKeySecret < ClientKeyExchange
        def self.read(_, io)
          encrypted_pre_master_secret = io.read_data :uint16
          self.new encrypted_pre_master_secret
        end

        def write(_, io)
          io.write_data :uint16, @encrypted_pre_master_secret
        end

        attr_reader :encrypted_pre_master_secret

        def initialize(encrypted_pre_master_secret)
          @encrypted_pre_master_secret = encrypted_pre_master_secret
        end
      end
    end
  end
end
