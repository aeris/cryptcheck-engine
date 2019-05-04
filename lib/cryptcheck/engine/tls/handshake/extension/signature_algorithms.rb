module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class SignatureAlgorithms
					ID = :signature_algorithms

					def self.read(io)
						read, schemes = Tls.read_signature_schemes io
						schemes = self.new schemes
						[read, schemes]
					end

					def write(io)
						Tls.write_signature_schemes io, @schemes
					end

					attr_reader :schemes

					def initialize(schemes)
						@schemes = schemes
					end

					def self.build(*schemes)
						self.new schemes
					end
				end
			end
		end
	end
end