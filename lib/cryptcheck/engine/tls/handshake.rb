module Cryptcheck::Engine
	module Tls
		class Handshake
			autoload :HelloRequest, 'cryptcheck/engine/tls/handshake/hello_request'
			autoload :ClientHello, 'cryptcheck/engine/tls/handshake/client_hello'

			ID = 0x16
			# 0x02 => :server_hello,
			# 0x0b => :certificate,
			# 0x0c => :server_key_exchange,
			# 0x0d => :certificate_request,
			# 0x0e => :server_hello_done,
			# 0x0f => :certificate_verify,
			# 0x10 => :client_key_exchange,
			# 0x14 => :finished
			TYPES = IdClasses.new(
					HelloRequest, # 0x00
					ClientHello, # 0x01
			).freeze

			def self.read(socket, *args, **kwargs)
				tmp  = socket.recv_uint8 *args, **kwargs
				type = TYPES[tmp]
				raise ProtocolError, "Unknown handshake type 0x#{tmp.to_s 16}" unless type

				size = 0
				3.times do
					size *= 16
					size += socket.recv_uint8 *args, **kwargs
				end

				record = type.read socket, *args, **kwargs
				self.new record
			end

			def write(socket, *args, **kwargs)
				socket.send_uint8 @record.class::ID, *args, **kwargs
				size = @record.size
				size = 3.times.collect { t = size % 16; size /= 16; t }.reverse
				size.each { |s| socket.send_uint8 s, *args, **kwargs }
				@record.write socket, *args, **kwargs
			end

			attr_reader :record

			def initialize(record)
				@record = record
			end

			def size
				4 + @record.size
			end
		end
	end
end
