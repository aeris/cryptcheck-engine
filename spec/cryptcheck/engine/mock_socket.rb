module Cryptcheck::Engine
	class MockSocket < BasicSocket
		def initialize(string = '')
			self.init string
		end

		def init(string = '')
			@buffer = StringIO.new self.class.from_hex string
		end

		def content
			@buffer.string
		end

		def sendmsg(data, *args, **kwargs)
			@buffer.write data
		end

		def recvmsg(length, *args, **kwargs)
			@buffer.read length
		end

		def self.from_hex(string)
			string.b.gsub(/\s/, '').scan(/../).collect { |h| h.hex.chr }.join.b
		end

		def self.to_hex(string)
			string.b.each_byte.map { |b| "%02x" % b.ord }.join.upcase
		end
	end
end
