module Cryptcheck::Engine
  module Tls
    class ChangeCipherSpec
      ID      = 0x14
      PAYLOAD = 0x01

      def self.read(_, io, _)
        payload = io.read_uint8
        raise ProtocolError, 'Expect change cipher spec payload to be 0x%02X, got 0x%02X' % [PAYLOAD, payload] unless payload == PAYLOAD
        self.new
      end

      def write(_, io)
        io.write_uint8 PAYLOAD
      end
    end
  end
end
