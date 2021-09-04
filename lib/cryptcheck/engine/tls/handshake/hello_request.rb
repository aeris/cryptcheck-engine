module Cryptcheck::Engine
  module Tls
    class Handshake
      class HelloRequest
        ID = 0x00

        def self.read(_, _)
          self.new
        end

        def write(_, _) end
      end
    end
  end
end
