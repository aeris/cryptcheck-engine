module Cryptcheck::Engine
  module Tls
    class ProtocolError < StandardError
    end

    class AlertError < StandardError
      attr_reader :alert

      def initialize(alert)
        @alert  = alert
        message = "[#{alert.level}] Alert #{alert.description}"
        super message
      end
    end

    # region Versions
    VERSIONS = DoubleHash.new(
      0x0300 => :ssl_3_0,
      0x0301 => :tls_1_0,
      0x0302 => :tls_1_1,
      0x0303 => :tls_1_2,
      0x0304 => :tls_1_3
    ).freeze
    # endregion

    def self.read_version(io)
      tmp     = io.read_uint16
      version = VERSIONS[tmp]
      raise ProtocolError, 'Unknown client version 0x%02X' % tmp unless version
      version
    end

    def self.write_version(io, version)
      tmp = VERSIONS.inverse version
      raise ProtocolError, 'Unknown client version %s' % version unless tmp
      io.write_uint16 tmp
    end

    # region Cipher suites
    CIPHERS = DoubleHash.new(
      0x0000 => :TLS_NULL_WITH_NULL_NULL,
      0x0001 => :TLS_RSA_WITH_NULL_MD5,
      0x0002 => :TLS_RSA_WITH_NULL_SHA,
      0x0003 => :TLS_RSA_EXPORT_WITH_RC4_40_MD5,
      0x0004 => :TLS_RSA_WITH_RC4_128_MD5,
      0x0005 => :TLS_RSA_WITH_RC4_128_SHA,
      0x0006 => :TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
      0x0007 => :TLS_RSA_WITH_IDEA_CBC_SHA,
      0x0008 => :TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x0009 => :TLS_RSA_WITH_DES_CBC_SHA,
      0x000A => :TLS_RSA_WITH_3DES_EDE_CBC_SHA,
      0x000B => :TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
      0x000C => :TLS_DH_DSS_WITH_DES_CBC_SHA,
      0x000D => :TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
      0x000E => :TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x000F => :TLS_DH_RSA_WITH_DES_CBC_SHA,
      0x0010 => :TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
      0x0011 => :TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
      0x0012 => :TLS_DHE_DSS_WITH_DES_CBC_SHA,
      0x0013 => :TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
      0x0014 => :TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x0015 => :TLS_DHE_RSA_WITH_DES_CBC_SHA,
      0x0016 => :TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
      0x0017 => :TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
      0x0018 => :TLS_DH_ANON_WITH_RC4_128_MD5,
      0x0019 => :TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
      0x001A => :TLS_DH_ANON_WITH_DES_CBC_SHA,
      0x001B => :TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
      0x001E => :TLS_KRB5_WITH_DES_CBC_SHA,
      0x001F => :TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
      0x0020 => :TLS_KRB5_WITH_RC4_128_SHA,
      0x0021 => :TLS_KRB5_WITH_IDEA_CBC_SHA,
      0x0022 => :TLS_KRB5_WITH_DES_CBC_MD5,
      0x0023 => :TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
      0x0024 => :TLS_KRB5_WITH_RC4_128_MD5,
      0x0025 => :TLS_KRB5_WITH_IDEA_CBC_MD5,
      0x0026 => :TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
      0x0027 => :TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
      0x0028 => :TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
      0x0029 => :TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
      0x002A => :TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
      0x002B => :TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
      0x002C => :TLS_PSK_WITH_NULL_SHA,
      0x002D => :TLS_DHE_PSK_WITH_NULL_SHA,
      0x002E => :TLS_RSA_PSK_WITH_NULL_SHA,
      0x002F => :TLS_RSA_WITH_AES_128_CBC_SHA,
      0x0030 => :TLS_DH_DSS_WITH_AES_128_CBC_SHA,
      0x0031 => :TLS_DH_RSA_WITH_AES_128_CBC_SHA,
      0x0032 => :TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
      0x0033 => :TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
      0x0034 => :TLS_DH_ANON_WITH_AES_128_CBC_SHA,
      0x0035 => :TLS_RSA_WITH_AES_256_CBC_SHA,
      0x0036 => :TLS_DH_DSS_WITH_AES_256_CBC_SHA,
      0x0037 => :TLS_DH_RSA_WITH_AES_256_CBC_SHA,
      0x0038 => :TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
      0x0039 => :TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      0x003A => :TLS_DH_ANON_WITH_AES_256_CBC_SHA,
      0x003B => :TLS_RSA_WITH_NULL_SHA256,
      0x003C => :TLS_RSA_WITH_AES_128_CBC_SHA256,
      0x003D => :TLS_RSA_WITH_AES_256_CBC_SHA256,
      0x003E => :TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
      0x003F => :TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
      0x0040 => :TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
      0x0041 => :TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0042 => :TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
      0x0043 => :TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0044 => :TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
      0x0045 => :TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0046 => :TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA,
      0x0067 => :TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      0x0068 => :TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
      0x0069 => :TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
      0x006A => :TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
      0x006B => :TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      0x006C => :TLS_DH_ANON_WITH_AES_128_CBC_SHA256,
      0x006D => :TLS_DH_ANON_WITH_AES_256_CBC_SHA256,
      0x0084 => :TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0085 => :TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
      0x0086 => :TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0087 => :TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
      0x0088 => :TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0089 => :TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA,
      0x008A => :TLS_PSK_WITH_RC4_128_SHA,
      0x008B => :TLS_PSK_WITH_3DES_EDE_CBC_SHA,
      0x008C => :TLS_PSK_WITH_AES_128_CBC_SHA,
      0x008D => :TLS_PSK_WITH_AES_256_CBC_SHA,
      0x008E => :TLS_DHE_PSK_WITH_RC4_128_SHA,
      0x008F => :TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
      0x0090 => :TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
      0x0091 => :TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
      0x0092 => :TLS_RSA_PSK_WITH_RC4_128_SHA,
      0x0093 => :TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
      0x0094 => :TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
      0x0095 => :TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
      0x0096 => :TLS_RSA_WITH_SEED_CBC_SHA,
      0x0097 => :TLS_DH_DSS_WITH_SEED_CBC_SHA,
      0x0098 => :TLS_DH_RSA_WITH_SEED_CBC_SHA,
      0x0099 => :TLS_DHE_DSS_WITH_SEED_CBC_SHA,
      0x009A => :TLS_DHE_RSA_WITH_SEED_CBC_SHA,
      0x009B => :TLS_DH_ANON_WITH_SEED_CBC_SHA,
      0x009C => :TLS_RSA_WITH_AES_128_GCM_SHA256,
      0x009D => :TLS_RSA_WITH_AES_256_GCM_SHA384,
      0x009E => :TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
      0x009F => :TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      0x00A0 => :TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
      0x00A1 => :TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
      0x00A2 => :TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
      0x00A3 => :TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
      0x00A4 => :TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
      0x00A5 => :TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
      0x00A6 => :TLS_DH_ANON_WITH_AES_128_GCM_SHA256,
      0x00A7 => :TLS_DH_ANON_WITH_AES_256_GCM_SHA384,
      0x00A8 => :TLS_PSK_WITH_AES_128_GCM_SHA256,
      0x00A9 => :TLS_PSK_WITH_AES_256_GCM_SHA384,
      0x00AA => :TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
      0x00AB => :TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
      0x00AC => :TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
      0x00AD => :TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
      0x00AE => :TLS_PSK_WITH_AES_128_CBC_SHA256,
      0x00AF => :TLS_PSK_WITH_AES_256_CBC_SHA384,
      0x00B0 => :TLS_PSK_WITH_NULL_SHA256,
      0x00B1 => :TLS_PSK_WITH_NULL_SHA384,
      0x00B2 => :TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
      0x00B3 => :TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
      0x00B4 => :TLS_DHE_PSK_WITH_NULL_SHA256,
      0x00B5 => :TLS_DHE_PSK_WITH_NULL_SHA384,
      0x00B6 => :TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
      0x00B7 => :TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
      0x00B8 => :TLS_RSA_PSK_WITH_NULL_SHA256,
      0x00B9 => :TLS_RSA_PSK_WITH_NULL_SHA384,
      0x00BA => :TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00BB => :TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
      0x00BC => :TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00BD => :TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
      0x00BE => :TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00BF => :TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256,
      0x00C0 => :TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00C1 => :TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
      0x00C2 => :TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00C3 => :TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
      0x00C4 => :TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00C5 => :TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256,
      0x00FF => :TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
      0x1301 => :TLS_AES_128_GCM_SHA256,
      0x1302 => :TLS_AES_256_GCM_SHA384,
      0x1303 => :TLS_CHACHA20_POLY1305_SHA256,
      0x1304 => :TLS_AES_128_CCM_SHA256,
      0x1305 => :TLS_AES_128_CCM_8_SHA256,
      0x5600 => :TLS_FALLBACK_SCSV,
      0xC001 => :TLS_ECDH_ECDSA_WITH_NULL_SHA,
      0xC002 => :TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
      0xC003 => :TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
      0xC004 => :TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
      0xC005 => :TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
      0xC006 => :TLS_ECDHE_ECDSA_WITH_NULL_SHA,
      0xC007 => :TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
      0xC008 => :TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
      0xC009 => :TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      0xC00A => :TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      0xC00B => :TLS_ECDH_RSA_WITH_NULL_SHA,
      0xC00C => :TLS_ECDH_RSA_WITH_RC4_128_SHA,
      0xC00D => :TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
      0xC00E => :TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
      0xC00F => :TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
      0xC010 => :TLS_ECDHE_RSA_WITH_NULL_SHA,
      0xC011 => :TLS_ECDHE_RSA_WITH_RC4_128_SHA,
      0xC012 => :TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
      0xC013 => :TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      0xC014 => :TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      0xC015 => :TLS_ECDH_ANON_WITH_NULL_SHA,
      0xC016 => :TLS_ECDH_ANON_WITH_RC4_128_SHA,
      0xC017 => :TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
      0xC018 => :TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
      0xC019 => :TLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
      0xC01A => :TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
      0xC01B => :TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
      0xC01C => :TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
      0xC01D => :TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
      0xC01E => :TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
      0xC01F => :TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
      0xC020 => :TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
      0xC021 => :TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
      0xC022 => :TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
      0xC023 => :TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
      0xC024 => :TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
      0xC025 => :TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
      0xC026 => :TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
      0xC027 => :TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
      0xC028 => :TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
      0xC029 => :TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
      0xC02A => :TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
      0xC02B => :TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      0xC02C => :TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      0xC02D => :TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
      0xC02E => :TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
      0xC02F => :TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      0xC030 => :TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      0xC031 => :TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
      0xC032 => :TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
      0xC033 => :TLS_ECDHE_PSK_WITH_RC4_128_SHA,
      0xC034 => :TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
      0xC035 => :TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
      0xC036 => :TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
      0xC037 => :TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
      0xC038 => :TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
      0xC039 => :TLS_ECDHE_PSK_WITH_NULL_SHA,
      0xC03A => :TLS_ECDHE_PSK_WITH_NULL_SHA256,
      0xC03B => :TLS_ECDHE_PSK_WITH_NULL_SHA384,
      0xC03C => :TLS_RSA_WITH_ARIA_128_CBC_SHA256,
      0xC03D => :TLS_RSA_WITH_ARIA_256_CBC_SHA384,
      0xC03E => :TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
      0xC03F => :TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
      0xC040 => :TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
      0xC041 => :TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
      0xC042 => :TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
      0xC043 => :TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
      0xC044 => :TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
      0xC045 => :TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
      0xC046 => :TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256,
      0xC047 => :TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384,
      0xC048 => :TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
      0xC049 => :TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
      0xC04A => :TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
      0xC04B => :TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
      0xC04C => :TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
      0xC04D => :TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
      0xC04E => :TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
      0xC04F => :TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
      0xC050 => :TLS_RSA_WITH_ARIA_128_GCM_SHA256,
      0xC051 => :TLS_RSA_WITH_ARIA_256_GCM_SHA384,
      0xC052 => :TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
      0xC053 => :TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
      0xC054 => :TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
      0xC055 => :TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
      0xC056 => :TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
      0xC057 => :TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
      0xC058 => :TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
      0xC059 => :TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
      0xC05A => :TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256,
      0xC05B => :TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384,
      0xC05C => :TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
      0xC05D => :TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
      0xC05E => :TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
      0xC05F => :TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
      0xC060 => :TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
      0xC061 => :TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
      0xC062 => :TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
      0xC063 => :TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
      0xC064 => :TLS_PSK_WITH_ARIA_128_CBC_SHA256,
      0xC065 => :TLS_PSK_WITH_ARIA_256_CBC_SHA384,
      0xC066 => :TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
      0xC067 => :TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
      0xC068 => :TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
      0xC069 => :TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
      0xC06A => :TLS_PSK_WITH_ARIA_128_GCM_SHA256,
      0xC06B => :TLS_PSK_WITH_ARIA_256_GCM_SHA384,
      0xC06C => :TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
      0xC06D => :TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
      0xC06E => :TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
      0xC06F => :TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
      0xC070 => :TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
      0xC071 => :TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
      0xC072 => :TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xC073 => :TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xC074 => :TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xC075 => :TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xC076 => :TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xC077 => :TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xC078 => :TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xC079 => :TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xC07A => :TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC07B => :TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC07C => :TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC07D => :TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC07E => :TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC07F => :TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC080 => :TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
      0xC081 => :TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
      0xC082 => :TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
      0xC083 => :TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
      0xC084 => :TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256,
      0xC085 => :TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384,
      0xC086 => :TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC087 => :TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC088 => :TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC089 => :TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC08A => :TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC08B => :TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC08C => :TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xC08D => :TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xC08E => :TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xC08F => :TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xC090 => :TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xC091 => :TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xC092 => :TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xC093 => :TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xC094 => :TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xC095 => :TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xC096 => :TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xC097 => :TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xC098 => :TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xC099 => :TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xC09A => :TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xC09B => :TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xC09C => :TLS_RSA_WITH_AES_128_CCM,
      0xC09D => :TLS_RSA_WITH_AES_256_CCM,
      0xC09E => :TLS_DHE_RSA_WITH_AES_128_CCM,
      0xC09F => :TLS_DHE_RSA_WITH_AES_256_CCM,
      0xC0A0 => :TLS_RSA_WITH_AES_128_CCM_8,
      0xC0A1 => :TLS_RSA_WITH_AES_256_CCM_8,
      0xC0A2 => :TLS_DHE_RSA_WITH_AES_128_CCM_8,
      0xC0A3 => :TLS_DHE_RSA_WITH_AES_256_CCM_8,
      0xC0A4 => :TLS_PSK_WITH_AES_128_CCM,
      0xC0A5 => :TLS_PSK_WITH_AES_256_CCM,
      0xC0A6 => :TLS_DHE_PSK_WITH_AES_128_CCM,
      0xC0A7 => :TLS_DHE_PSK_WITH_AES_256_CCM,
      0xC0A8 => :TLS_PSK_WITH_AES_128_CCM_8,
      0xC0A9 => :TLS_PSK_WITH_AES_256_CCM_8,
      0xC0AA => :TLS_PSK_DHE_WITH_AES_128_CCM_8,
      0xC0AB => :TLS_PSK_DHE_WITH_AES_256_CCM_8,
      0xC0AC => :TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
      0xC0AD => :TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
      0xC0AE => :TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
      0xC0AF => :TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
      0xC0B0 => :TLS_ECCPWD_WITH_AES_128_GCM_SHA256,
      0xC0B1 => :TLS_ECCPWD_WITH_AES_256_GCM_SHA384,
      0xC0B2 => :TLS_ECCPWD_WITH_AES_128_CCM_SHA256,
      0xC0B3 => :TLS_ECCPWD_WITH_AES_256_CCM_SHA384,
      0xC0B4 => :TLS_SHA256_SHA256,
      0xC0B5 => :TLS_SHA384_SHA384,
      0xC100 => :TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,
      0xC101 => :TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC,
      0xC102 => :TLS_GOSTR341112_256_WITH_28147_CNT_IMIT,
      0xCCA8 => :TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      0xCCA9 => :TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      0xCCAA => :TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      0xCCAB => :TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xCCAC => :TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xCCAD => :TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xCCAE => :TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xD001 => :TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
      0xD002 => :TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
      0xD003 => :TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
      0xD005 => :TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
    ).freeze
    # endregion

    def self.read_cipher(io)
      tmp    = io.read_uint16
      cipher = CIPHERS[tmp]
      raise ProtocolError, 'Unknown cipher 0x%04X' % tmp unless cipher
      cipher
    end

    def self.read_ciphers(io)
      io.collect(:uint16) { self.read_cipher io }
    end

    def self.write_cipher(io, cipher)
      tmp = CIPHERS.inverse cipher
      raise ProtocolError, 'Unknown cipher %s' % cipher unless tmp
      io.write_uint16 tmp
    end

    def self.write_ciphers(io, ciphers)
      io2 = StringIO.new
      ciphers.each { |c| self.write_cipher io2, c }
      io.write_data :uint16, io2.string
    end

    COMPRESSIONS = DoubleHash.new(
      0x00 => :NULL,
      0x01 => :DEFLATE,
      0x64 => :LZS
    ).freeze

    def self.read_compression(io)
      tmp         = io.read_uint8
      compression = COMPRESSIONS[tmp]
      raise ProtocolError, 'Unknown compression 0x%02X' % tmp unless compression
      compression
    end

    def self.read_compressions(io)
      io.collect(:uint8) { self.read_compression io }
    end

    def self.write_compression(io, compression)
      tmp = COMPRESSIONS.inverse compression
      raise ProtocolError, 'Unknown compression %s' % compression unless tmp
      io.write_uint8 tmp
    end

    def self.write_compressions(io, compressions)
      io2 = StringIO.new
      compressions.each { |c| self.write_compression io2, c }
      io.write_data :uint8, io2.string
    end

    # region Groups
    GROUPS = DoubleHash.new(
      0x0001 => :sect163k1,
      0x0002 => :sect163r1,
      0x0003 => :sect163r2,
      0x0004 => :sect193r1,
      0x0005 => :sect193r2,
      0x0006 => :sect233k1,
      0x0007 => :sect233r1,
      0x0008 => :sect239k1,
      0x0009 => :sect283k1,
      0x000A => :sect283r1,
      0x000B => :sect409k1,
      0x000C => :sect409r1,
      0x000D => :sect571k1,
      0x000E => :sect571r1,
      0x000F => :secp160k1,
      0x0010 => :secp160r1,
      0x0011 => :secp160r2,
      0x0012 => :secp192k1,
      0x0013 => :secp192r1,
      0x0014 => :secp224k1,
      0x0015 => :secp224r1,
      0x0016 => :secp256k1,
      0x0017 => :secp256r1,
      0x0018 => :secp384r1,
      0x0019 => :secp521r1,
      0x001A => :brainpoolP256r1,
      0x001B => :brainpoolP384r1,
      0x001C => :brainpoolP512r1,
      0x001D => :x25519,
      0x001E => :x448,
      0x001F => :brainpoolP256r1,
      0x0020 => :brainpoolP384r1,
      0x0021 => :brainpoolP512r1,
      0x0022 => :GC256A,
      0x0023 => :GC256B,
      0x0024 => :GC256C,
      0x0025 => :GC256D,
      0x0026 => :GC512A,
      0x0027 => :GC512B,
      0x0028 => :GC512C,
      0x0100 => :ffdhe2048,
      0x0101 => :ffdhe3072,
      0x0102 => :ffdhe4096,
      0x0103 => :ffdhe6144,
      0x0104 => :ffdhe8192,
      0xFF01 => :arbitrary_explicit_prime_curves,
      0xFF02 => :arbitrary_explicit_char2_curves,
    ).freeze
    # endregion

    def self.read_group(io)
      tmp   = io.read_uint16
      group = GROUPS[tmp]
      raise ProtocolError, 'Unknown group 0x%04X' % tmp unless group
      group
    end

    def self.read_groups(io)
      io.collect(:uint16) { self.read_group io }
    end

    def self.write_group(io, group)
      id = GROUPS.inverse group
      raise ProtocolError, 'Unknown group %s' % group unless id
      io.write_uint16 id
    end

    def self.write_groups(io, groups)
      io2 = StringIO.new
      groups.each { |g| self.write_group io2, g }
      io.write_data :uint16, io2.string
    end

    # region Signature algorithms
    SIGNATURE_ALGORITHMS = DoubleHash.new(
      0x00 => :anonymous,
      0x01 => :rsa,
      0x02 => :dsa,
      0x03 => :ecdsa,
      0x07 => :ed25519,
      0x08 => :ed448,
      0x40 => :gostr34102012_256,
      0x41 => :gostr34102012_512
    ).freeze
    # endregion

    # region Hash algorithms
    HASH_ALGORITHMS = DoubleHash.new(
      0x00 => :none,
      0x01 => :md5,
      0x02 => :sha1,
      0x03 => :sha224,
      0x04 => :sha256,
      0x05 => :sha384,
      0x06 => :sha512,
      0x08 => :Intrinsic,
    ).freeze
    # endregion

    # region Signature schemes
    SIGNATURE_SCHEMES = DoubleHash.new(
      0x0201 => :rsa_pkcs1_sha1,
      0x0203 => :ecdsa_sha1,
      0x0401 => :rsa_pkcs1_sha256,
      0x0403 => :ecdsa_secp256r1_sha256,
      0x0501 => :rsa_pkcs1_sha384,
      0x0503 => :ecdsa_secp384r1_sha384,
      0x0601 => :rsa_pkcs1_sha512,
      0x0603 => :ecdsa_secp521r1_sha512,
      0x0804 => :rsa_pss_rsae_sha256,
      0x0805 => :rsa_pss_rsae_sha384,
      0x0806 => :rsa_pss_rsae_sha512,
      0x0807 => :ed25519,
      0x0808 => :ed448,
      0x0809 => :rsa_pss_pss_sha256,
      0x080A => :rsa_pss_pss_sha384,
      0x080B => :rsa_pss_pss_sha512,
      0x081A => :ecdsa_brainpoolP256r1_sha256,
      0x081B => :ecdsa_brainpoolP384r1_sha384,
      0x081C => :ecdsa_brainpoolP512r1_sha512,
    )
    # endregion

    # region Curve types
    CURVE_TYPES = DoubleHash.new(
      0x01 => :explicit_prime,
      0x02 => :explicit_char2,
      0x03 => :named_curve,
    )
    # endregion

    def self.read_curve_type(io)
      tmp  = io.read_uint8
      type = CURVE_TYPES[tmp]
      raise ProtocolError, 'Unknown curve type 0x%02X' % tmp unless type
      type
    end

    def self.write_curve_type(io, type)
      id = CURVE_TYPES.inverse type
      raise ProtocolError, 'Unknown curve type %s' % type unless id
      io.write_uint8 id
    end

    autoload :Context, 'cryptcheck/engine/tls/context'
    autoload :RecordHeader, 'cryptcheck/engine/tls/record_header'
    autoload :Handshake, 'cryptcheck/engine/tls/handshake'
    autoload :ChangeCipherSpec, 'cryptcheck/engine/tls/change_cipher_spec'
    autoload :Signature, 'cryptcheck/engine/tls/signature'
    autoload :Alert, 'cryptcheck/engine/tls/alert'
    autoload :Application, 'cryptcheck/engine/tls/application'

    def self.read(context, io)
      header = RecordHeader.read context, io
      record_type = header.type
      record = record_type.read context, io, header.length
      raise AlertError, record if record.is_a? Alert
      [header, record]
    end

    def self.write(context, io, version, record)
      io2 = StringIO.new
      record.write context, io2

      type   = record.class
      length = io2.size
      header = RecordHeader.new type, version, length

      header.write context, io
      io.write io2.string
    end

    def self.read_handshake(context, io, expected = nil)
      header, handshake = self.read context, io
      klass             = handshake.class
      raise ProtocolError, "Expecting #{Handshake}, got #{klass}" unless handshake.is_a? Handshake
      record = handshake.record
      klass  = record.class
      raise ProtocolError, "Expecting #{expected}, got #{klass}" if expected && !klass.kind_of?(expected)
      [header, record]
    end

    def self.write_handshake(context, io, record)
      version = context.client.version
      record  = Handshake.new record
      self.write context, io, version, record
    end

    def self.handshake(context, io)
      client = context.client
      server = context.server

      client_random = SecureRandom.bytes 32
      client.random = client_random

      client_hello = ClientHello.new client.version, client_random, client.session, client.ciphers, client.compressions, client.extensions
      client_hello.write io

      server_hello       = self.read_handshake context, io, ServerHello
      server.version     = server_hello.version
      server.random      = server_hello.random
      server.session     = server_hello.session
      server.cipher      = server_hello.cipher
      server.compression = server_hello.compression
      server.extensions  = server_hello.extensions

      record              = self.read_handshake context, io, Certificate
      server.certificates = record.certificates

      server_key = self.read_handshake context, io, ServerKeyExchange
      server.key = server_key

      self.read_handshake context, io, ServerHelloDone

      # client_key = ClientKeyExchange.build()
      self.write_handshake context, io, client_key

      self.write_handshake context, io, ChangeCipherSpec.new
      # self.write_handshake context, io, Finished.new

      self.read_handshake context, io, ChangeCipherSpec
      # self.read_handshake context, io, Finished
    end
  end
end
