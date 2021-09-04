module Cryptcheck::Engine
  module Tls
    class Signature
      def self.read_scheme(io)
        tmp    = io.read_uint16
        scheme = SIGNATURE_SCHEMES[tmp]
        raise ProtocolError, 'Unknown signature scheme 0x%04X' % tmp unless scheme
        scheme
      end

      def self.read_schemes(io)
        io.collect(:uint16) { self.read_scheme io }
      end

      def self.write_scheme(io, scheme)
        id = SIGNATURE_SCHEMES.inverse scheme
        raise ProtocolError, 'Unknown signature scheme %s' % scheme unless id
        io.write_uint16 id
      end

      def self.write_schemes(io, schemes)
        io2 = StringIO.new
        schemes.each { |s| self.write_scheme io2, s }
        io.write_data :uint16, io2.string
      end

      def self.read(io)
        scheme    = self.read_scheme io
        signature = io.read_data :uint16
        self.new scheme, signature
      end

      def write(io)
        self.class.write_scheme io, @scheme
        io.write_data :uint16, @signature
      end

      attr_reader :scheme, :signature

      def initialize(scheme, signature)
        @scheme    = scheme
        @signature = signature
      end
    end
  end
end
