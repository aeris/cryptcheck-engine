module Cryptcheck::Engine
	class MockIO < StringIO
		def init(string = '')
			self.string = string.from_hex
		end
	end
end
