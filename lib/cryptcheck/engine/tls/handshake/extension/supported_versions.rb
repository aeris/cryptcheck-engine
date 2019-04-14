module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class SupportedVersions
					ID = :supported_versions

					def self.read(io)
						read        = 0
						r, length   = io.read_uint8
						read        += r
						r, versions = io.collect length do
							r, tmp  = io.read_uint16
							version = VERSIONS[tmp]
							raise ProtocolError, 'Unknown version 0x%04X' % tmp unless version
							[r, version]
						end
						read        += r
						versions    = self.new versions
						[read, versions]
					end

					def write(io)
						io2 = StringIO.new
						@versions.each do |version|
							id = VERSIONS.inverse version
							io2.write_uint16 id
						end

						written = 0
						written += io.write_uint8 io2.size
						written += io.write io2.string
						written
					end

					attr_reader :versions

					def initialize(versions)
						@versions = versions
					end

					def self.build(*versions)
						self.new versions
					end
				end
			end
		end
	end
end
