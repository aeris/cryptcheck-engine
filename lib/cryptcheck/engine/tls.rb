module Cryptcheck
	module Engine
		module Tls
			class ProtocolError < StandardError
			end

			autoload :RecordHeader, 'cryptcheck/engine/tls/record_header'
			autoload :Handshake, 'cryptcheck/engine/tls/handshake'

			def self.read(socket, *args, **kwargs)
				header = RecordHeader.read socket, *args, **kwargs
				record = header.type.read socket, *args, **kwargs
				[header, record]
			end

			def self.write(socket, version, record, *args, **kwargs)
				type   = record.class
				length = record.size
				header = RecordHeader.new type, version, length
				header.write socket, *args, **kwargs
				record.write socket, *args, **kwargs
			end
		end
	end
end
