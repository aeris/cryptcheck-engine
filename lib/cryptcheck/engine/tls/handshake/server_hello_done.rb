module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerHelloDone
				ID = 0x0E

				def self.read(_)
					[0, self.new]
				end

				def write(_)
					0
				end
			end
		end
	end
end
