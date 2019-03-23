module Cryptcheck
	module Engine
		module Tls
			class ProtocolError < StandardError
			end

			autoload :RecordHeader, 'cryptcheck/engine/tls/record_header'
			autoload :Record, 'cryptcheck/engine/tls/record'
		end
	end
end
