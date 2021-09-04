module Cryptcheck::Engine
  module Tls
    class Alert
      ID = 0x15

      LEVELS = DoubleHash.new(
        0x01 => :warning,
        0x02 => :fatal
      )

      DESCRIPTIONS = DoubleHash.new(
        0x00 => :close_notify,
        0x0A => :unexpected_message,
        0x14 => :bad_record_mac,
        0x15 => :decryption_failed,
        0x16 => :record_overflow,
        0x1E => :decompression_failure,
        0x28 => :handshake_failure,
        0x29 => :no_certificate,
        0x2B => :unsupported_certificate,
        0x2C => :certificate_revoked,
        0x2D => :certificate_expired,
        0x2E => :certificate_unknown,
        0x2F => :illegal_parameter,
        0x30 => :unknown_ca,
        0x31 => :access_denied,
        0x32 => :decode_error,
        0x33 => :decrypt_error,
        0x3C => :export_restriction,
        0x46 => :protocol_version,
        0x47 => :insufficient_security,
        0x50 => :internal_error,
        0x5A => :user_canceled,
        0x64 => :no_renegociation,
        0x6E => :unsupported_extension,
      )

      attr_reader :level, :description

      def initialize(level, description)
        @level       = level
        @description = description
      end

      def self.read(_, io, _)
        tmp   = io.read_uint8
        level = LEVELS[tmp]
        raise ProtocolError, 'Unknown alert level 0x%02X' % tmp unless level

        tmp         = io.read_uint8
        description = DESCRIPTIONS[tmp]
        raise ProtocolError, 'Unknown alert description 0x%02X' % tmp unless description

        self.new level, description
      end

      def write(_, io)
        io.write_uint8 LEVELS.inverse @level
        io.write_uint8 DESCRIPTIONS.inverse @description
      end
    end
  end
end
