module Cryptcheck::Engine
	module Tls
		class Handshake
			class HelloRequest
				ID = 0x00

				def self.read(_)
					self.new
				end

				def write(_)
				end
			end
		end
	end
end
