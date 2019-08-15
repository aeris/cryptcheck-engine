module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerHelloDone
				ID = 0x0E

				def self.read(_, _)
					self.new
				end

				def write(_, _)
				end
			end
		end
	end
end
