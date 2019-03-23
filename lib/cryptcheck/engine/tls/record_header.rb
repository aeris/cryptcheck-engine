module Cryptcheck
	module Engine
		module Tls
			class RecordHeader
				CONTENT_TYPES = DoubleHash.new 0x14 => :change_cipher_spec,
											   0x15 => :alert,
											   0x16 => :handshake,
											   0x17 => :application,
											   0x18 => :heartbeat

				VERSIONS = DoubleHash.new 0x0300 => :ssl_3_0,
										  0x0301 => :tls_1_0,
										  0x0302 => :tls_1_1,
										  0x0303 => :tls_1_2,
										  0x0304 => :tls_1_3

				def self.read(socket, timeout: nil)
					tmp  = socket.recv_uint8 timeout: timeout
					type = CONTENT_TYPES[tmp]
					raise ProtocolError, "Unknown content type 0x#{tmp.to_s(16)}" unless type

					tmp     = socket.recv_uint16 timeout: timeout
					version = VERSIONS[tmp]
					raise ProtocolError, "Unknown version 0x#{tmp.to_s(16)}" unless version

					length = socket.recv_uint16 timeout: timeout

					new type, version, length
				end

				def write(socket, timeout: nil)
					tmp  = self.type
					type = CONTENT_TYPES.inverse tmp
					raise ProtocolError, "Unknown content type #{tmp}" unless type
					socket.send_uint8 type, timeout: timeout

					tmp     = self.version
					version = VERSIONS.inverse tmp
					raise ProtocolError, "Unknown version #{tmp}" unless version
					socket.send_uint16 version, timeout: timeout

					socket.send_uint16 self.length, timeout: timeout
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
