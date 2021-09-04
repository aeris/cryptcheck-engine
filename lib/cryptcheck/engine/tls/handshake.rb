module Cryptcheck::Engine
  module Tls
    class Handshake
      autoload :HelloRequest, 'cryptcheck/engine/tls/handshake/hello_request'
      autoload :Extension, 'cryptcheck/engine/tls/handshake/extension'
      autoload :ClientHello, 'cryptcheck/engine/tls/handshake/client_hello'
      autoload :ServerHello, 'cryptcheck/engine/tls/handshake/server_hello'
      autoload :Certificate, 'cryptcheck/engine/tls/handshake/certificate'
      autoload :ServerKeyExchange, 'cryptcheck/engine/tls/handshake/server_key_exchange'
      autoload :DhServerKeyExchange, 'cryptcheck/engine/tls/handshake/server_key_exchange'
      autoload :EcdhServerKeyExchange, 'cryptcheck/engine/tls/handshake/server_key_exchange'
      autoload :ServerHelloDone, 'cryptcheck/engine/tls/handshake/server_hello_done'
      autoload :ClientKeyExchange, 'cryptcheck/engine/tls/handshake/client_key_exchange'

      ID = 0x16

      # 0x0d => :certificate_request,
      # 0x0f => :certificate_verify,
      # 0x14 => :finished
      TYPES = IdClasses.new(
        HelloRequest, # 0x00
        ClientHello, # 0x01
        ServerHello, # 0x02
        Certificate, # 0x0B
        ServerKeyExchange, # 0x0C
        ServerHelloDone, # 0x0E
        ClientKeyExchange, # 0x10
      ).freeze

      def self.read(context, io, _)
        tmp  = io.read_uint8
        type = TYPES[tmp]
        raise ProtocolError, 'Unknown handshake type 0x%02X' % tmp unless type

        io.read_uint 3

        record = type.read context, io
        self.new record
      end

      def write(context, io)
        io2 = StringIO.new
        @record.write context, io2
        io.write_uint8 @record.class::ID
        io.write_data 3, io2.string
      end

      attr_reader :record

      def initialize(record)
        @record = record
      end
    end
  end
end
