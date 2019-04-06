module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				autoload :ServerName, 'cryptcheck/engine/tls/handshake/extension/server_name'
				autoload :SupportedGroup, 'cryptcheck/engine/tls/handshake/extension/supported_group'

				EXTENSIONS = IdClasses.new(
						ServerName,
						SupportedGroup
				).freeze

				def self.read(socket, *args, **kwargs)
					id     = socket.recv_uint16 *args, **kwargs
					length = socket.recv_uint16 *args, **kwargs

					clazz = EXTENSIONS[id]
					if clazz
						clazz.read socket, *args, **kwargs
					else
						data = socket.recvmsg length, *args, **kwargs
						Extension.new id, data
					end
				end

				def self.write(extension, socket, *args, **kwargs)
					# binding.pry
					id = if extension.is_a? Extension
							 extension.id
						 else
							 extension.class::ID
						 end
					socket.send_uint16 id, *args, **kwargs
					socket.send_uint16 extension.size, *args, **kwargs
					extension.write socket, *args, **kwargs
				end

				def write(socket, *args, **kwargs)
					socket.sendmsg @data, *args, **kwargs
				end

				attr_reader :id, :data

				def initialize(id, data)
					@id   = id
					@data = data
				end

				def size
					@size ||= @data.size
				end
			end
		end
	end
end
