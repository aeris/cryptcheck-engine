module Cryptcheck::Engine
	class MockSocket < BasicSocket
		def initialize(string = '')
			self.init string
		end

		def init(string = '')
			@buffer = StringIO.new string.from_hex
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
	end
end
