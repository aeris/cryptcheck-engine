module Cryptcheck::Engine
	module Tls
		class Handshake
			autoload :HelloRequest, 'cryptcheck/engine/tls/handshake/hello_request'
			autoload :Extension, 'cryptcheck/engine/tls/handshake/extension'
			autoload :ClientHello, 'cryptcheck/engine/tls/handshake/client_hello'
			autoload :ServerHello, 'cryptcheck/engine/tls/handshake/server_hello'

			ID = 0x16
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
					ServerHello, # 0x02
			).freeze

			def self.read(io)
				read   = 0
				r, tmp = io.read_uint8
				read   += r

				type = TYPES[tmp]
				raise ProtocolError, 'Unknown handshake type 0x%04X' % tmp unless type

				r, _ = io.read_uint 3
				read += r

				r, record = type.read io
				read      += r
				record    = self.new record

				[read, record]
			end

			def write(io)
				written = 0
				io2     = StringIO.new
				written += @record.write io2

				written += io.write_uint8 @record.class::ID
				written += io.write_data 3, io2.string

				written
			end

			attr_reader :record

			def initialize(record)
				@record = record
			end
		end
	end
end
