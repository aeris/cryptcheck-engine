module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class SignatureAlgorithms
					ID = :signature_algorithms

					def self.read(io)
						read      = 0
						r, length = io.read_uint16
						read      += r
						r, signs  = io.collect length do
							r, tmp = io.read_uint16
							sign   = SIGNATURE_SCHEMES[tmp]
							raise ProtocolError, 'Unknown signature scheme 0x%04X' % tmp unless sign
							[r, sign]
						end
						read      += r
						signs     = self.new signs
						[read, signs]
					end

					def write(io)
						io2 = StringIO.new
						@signs.each do |sign|
							id = SIGNATURE_SCHEMES.inverse sign
							io2.write_uint16 id
						end

						written = 0
						written += io.write_uint16 io2.size
						written += io.write io2.string
						written
					end

					attr_reader :signs

					def initialize(signs)
						@signs = signs
					end

					def self.build(*signs)
						self.new signs
					end
				end
			end
		end
	end
end
