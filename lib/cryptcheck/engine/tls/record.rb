module Cryptcheck
	module Engine
		module Tls
			class Record
				def self.read(socket, timeout: nil)
					header = RecordHeader.read socket, timeout: timeout
					length = header.length
					data   = socket.recvmsg length, timeout: timeout
					self.new header, data
				end

				def write(socket, timeout: nil)
					self.header.write socket, timeout: timeout
					socket.sendmsg self.data, timeout: timeout
				end

				attr_reader :header, :data

				def initialize(header, data)
					@header = header
					@data   = data

					expected_length = header.length
					real_length     = data.size
					raise Error, "Inconsistency between header length (#{expected_length}) and data length (#{real_length})" unless expected_length == real_length
				end
			end
		end
	end
end
