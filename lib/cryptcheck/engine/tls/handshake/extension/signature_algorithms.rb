module Cryptcheck::Engine
  module Tls
    class Handshake
      class Extension
        class SignatureAlgorithms
          ID = :signature_algorithms

          def self.read(io)
            schemes = Signature.read_schemes io
            self.new schemes
          end

          def write(io)
            Signature.write_schemes io, @schemes
          end

          attr_reader :schemes

          def initialize(schemes)
            @schemes = schemes
          end

          def self.build(*schemes)
            self.new schemes
          end
        end
      end
    end
  end
end
