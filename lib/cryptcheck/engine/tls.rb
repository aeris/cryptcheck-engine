module Cryptcheck
	module Engine
		module Tls
			class ProtocolError < StandardError
			end

			autoload :RecordHeader, 'cryptcheck/engine/tls/record_header'
			autoload :Handshake, 'cryptcheck/engine/tls/handshake'

			def self.read(io)
				read      = 0
				r, header = RecordHeader.read io
				read      += r
				r, record = header.type.read io
				read      += r
				[read, header, record]
			end

			def self.write(io, version, record)
				io2 = StringIO.new
				record.write io2

				type   = record.class
				length = io2.size
				header = RecordHeader.new type, version, length

				written = 0
				written += header.write io
				written += io.write io2.string
				written
			end
		end
	end
end
