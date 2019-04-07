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

				def self.read(io)
					read      = 0
					r, id     = io.read_uint16
					read      += r
					r, length = io.read_uint16
					read      += r

					clazz        = EXTENSIONS[id]
					r, extension = if clazz
									   clazz.read io
								   else
									   data      = io.read length
									   extension = Extension.new id, data
									   [length, extension]
								   end
					read         += r

					[read, extension]
				end

				def self.write(io, extension)
					io2 = StringIO.new
					extension.write io2

					id      = case extension
							  when Extension
								  extension.id
							  else
								  extension.class::ID
							  end
					written = 0
					written += io.write_uint16 id
					written += io.write_data :uint16, io2.string
					written
				end

				def write(io)
					io.write @data
				end

				attr_reader :id, :data

				def initialize(id, data)
					@id   = id
					@data = data
				end
			end
		end
	end
end
