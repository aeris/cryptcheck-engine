module Cryptcheck::Engine
	module Tls
		class Handshake
			class HelloRequest
				ID = 0x00

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
