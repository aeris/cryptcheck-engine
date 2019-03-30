module Cryptcheck::Engine
	module Tls
		class Handshake
			class ClientHello
				ID = 0x01

				def self.read(socket, *args, **kwargs)
					time = socket.recv_uint32 *args, **kwargs
					time = Time.at time

					random = socket.recvmsg 28, *args, **kwargs

					self.new time, random
				end

				def write(socket, *args, **kwargs)
					socket.send_uint32 @time.to_i, *args, **kwargs
					socket.sendmsg @random, *args, **kwargs
				end

				def size
					32
				end

				attr_reader :time, :random

				def initialize(time, random)
					@time   = time
					@random = random
				end
			end
		end
	end
end
