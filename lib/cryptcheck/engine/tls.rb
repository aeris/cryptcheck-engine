module Cryptcheck::Engine::Tls
	class SslRecordHeader
		def self.read(socket)
			socket.read
		end

		private

		def initialize()
		end
	end
end
