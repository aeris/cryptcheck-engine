module Cryptcheck::Engine
  module Tls
    class RecordHeader
      # 0x17 => :application
      # 0x18 => :heartbeat
      CONTENT_TYPES = IdClasses.new(
        Handshake, # 0x16
        ChangeCipherSpec, # 0x14
        Alert, # 0x15
        Application, # 0x17
      ).freeze

      def self.read(_, io)
        tmp  = io.read_uint8
        type = CONTENT_TYPES[tmp]
        raise ProtocolError, 'Unknown content type 0x%02X' % tmp unless type

        tmp     = io.read_uint16
        version = VERSIONS[tmp]
        raise ProtocolError, 'Unknown version 0x%04X' % tmp unless version

        length = io.read_uint16

        self.new type, version, length
      end

      def write(_, io)
        io.write_uint8 self.type::ID

        tmp     = self.version
        version = VERSIONS.inverse tmp
        raise ProtocolError, "Unknown version #{tmp}" unless version
        io.write_uint16 version

        io.write_uint16 self.length
      end

      attr_reader :type, :version, :length

      def initialize(type, version, length)
        tmp = CONTENT_TYPES.inverse type
        raise Error, "Unknown content type #{type}" unless tmp
        tmp = VERSIONS.inverse version
        raise Error, "Unknown version #{version}" unless tmp
        @type, @version, @length = type, version, length
      end
    end
  end
end
