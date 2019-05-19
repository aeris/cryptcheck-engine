module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerHelloDone
				ID = 0x0E

				def self.read(_)
					self.new
				end

				def write(_)
				end
			end
		end
	end
end
