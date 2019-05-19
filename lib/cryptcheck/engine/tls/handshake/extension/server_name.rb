module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class ServerName
					ID = :server_name

					NAME_TYPE = DoubleHash.new(
							0x00 => :hostname
					).freeze

					def self.read(io)
						names = io.collect :uint16 do
							tmp  = io.read_uint8
							type = NAME_TYPE[tmp]
							raise ProtocolError, 'Unknown name type 0x%02X' % tmp unless type

							hostname = io.read_data :uint16
							{ type: type, hostname: hostname }
						end
						self.new names
					end

					def write(io)
						io2 = StringIO.new
						@names.each do |name|
							type = name[:type]
							type = NAME_TYPE.inverse type
							io2.write_uint8 type
							hostname = name[:hostname]
							io2.write_data :uint16, hostname
						end
						io.write_data :uint16, io2.string
					end

					attr_reader :names

					def initialize(names)
						@names = names
					end

					def self.build(*hostnames)
						self.new hostnames.collect { |h| { type: :hostname, hostname: h } }
					end
				end
			end
		end
	end
end
