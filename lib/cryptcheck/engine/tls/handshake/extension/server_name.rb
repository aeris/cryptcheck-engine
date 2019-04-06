module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				class ServerName
					ID = 0x0000

					NAME_TYPE = DoubleHash.new(
							0x00 => :hostname
					).freeze

					def self.read(socket, *args, **kwargs)
						length = socket.recv_uint16 *args, **kwargs
						names  = socket.collect length do
							tmp  = socket.recv_uint8 *args, **kwargs
							type = NAME_TYPE[tmp]
							raise ProtocolError, "Unknown name type 0x#{tmp.to_s 16}" unless type

							length   = socket.recv_uint16 *args, **kwargs
							hostname = socket.recvmsg length, *args, **kwargs
							name     = { type: type, hostname: hostname }
							[3 + length, name]
						end
						self.new names
					end

					def write(socket, *args, **kwargs)
						size = self.size
						socket.send_uint16 size - 2, *args, **kwargs
						@names.each do |name|
							type = name[:type]
							type = NAME_TYPE.inverse type
							socket.send_uint8 type, *args, **kwargs
							hostname = name[:hostname]
							socket.send_uint16 hostname.size, *args, **kwargs
							socket.sendmsg hostname, *args, **kwargs
						end
					end

					attr_reader :names

					def initialize(names)
						@names = names
					end

					def size
						@size ||= 2 + @names.collect { |n| 3 + n[:hostname].size }.inject(:+)
					end
				end
			end
		end
	end
end
