module Cryptcheck
	module Engine
		module Tls
			class RecordHeader
				# 0x14 => :change_cipher_spec
				# 0x15 => :alert
				# 0x17 => :application
				# 0x18 => :heartbeat
				CONTENT_TYPES = IdClasses.new(
						Handshake, # 0x16
				).freeze

				VERSIONS = DoubleHash.new(0x0300 => :ssl_3_0,
										  0x0301 => :tls_1_0,
										  0x0302 => :tls_1_1,
										  0x0303 => :tls_1_2,
										  0x0304 => :tls_1_3).freeze

				def self.read(io)
					read   = 0
					r, tmp = io.read_uint8
					read   += r
					type   = CONTENT_TYPES[tmp]
					raise ProtocolError, "Unknown content type 0x#{tmp.to_s 16}" unless type

					r, tmp  = io.read_uint16
					read    += r
					version = VERSIONS[tmp]
					raise ProtocolError, "Unknown version 0x#{tmp.to_s 16}" unless version

					r, length = io.read_uint16
					read      += r

					header = self.new type, version, length
					[read, header]
				end

				def write(io)
					written = 0
					written += io.write_uint8 self.type::ID

					tmp     = self.version
					version = VERSIONS.inverse tmp
					raise ProtocolError, "Unknown version #{tmp}" unless version
					written += io.write_uint16 version

					written += io.write_uint16 self.length
					written
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
end
