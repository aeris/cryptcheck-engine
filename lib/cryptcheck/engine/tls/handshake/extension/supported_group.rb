module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class SupportedGroup
					ID = 0x000A

					GROUPS = DoubleHash.new({
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
											}).freeze

					def self.read(io)
						read      = 0
						r, length = io.read_uint16
						read      += r
						r, groups = io.collect length do
							r, tmp = io.read_uint16
							group  = GROUPS[tmp]
							raise ProtocolError, 'Unknown group 0x%04X' % tmp unless group
							[r, group]
						end
						read      += r
						groups    = self.new groups
						[read, groups]
					end

					def write(io)
						io2 = StringIO.new
						@groups.each do |group|
							id = GROUPS.inverse group
							io2.write_uint16 id
						end

						written = 0
						written += io.write_uint16 io2.size
						written += io.write io2.string
						written
					end

					attr_reader :groups

					def initialize(groups)
						@groups = groups
					end
				end
			end
		end
	end
end
