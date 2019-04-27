module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class RenegotiationInfo
					ID = :renegotiation_info

					def self.read(io)
						read, verify_data = io.read_data :uint8
						extension         = self.new verify_data
						[read, extension]
					end

					def write(io)
						io.write_data :uint8, @verify_data
					end

					attr_reader :verify_data

					def initialize(verify_data)
						@verify_data = verify_data
					end

					def self.build(verify_data = nil)
						self.new verify_data
					end
				end
			end
		end
	end
end
