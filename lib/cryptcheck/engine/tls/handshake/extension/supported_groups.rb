module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class SupportedGroups
					ID = :supported_groups

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

					def self.build(*curves)
						self.new curves
					end
				end
			end
		end
	end
end
