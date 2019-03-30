module Cryptcheck::Engine
	module Tls
		class Handshake
			class HelloRequest
				ID = 0x00

				def self.read(_, *_, **__)
					self.new
				end

				def write(_, *_, **__)
				end

				def size
					0
				end
			end
		end
	end
end
