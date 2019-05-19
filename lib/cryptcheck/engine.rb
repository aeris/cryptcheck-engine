require 'cryptcheck/engine/version'

module Cryptcheck
	module Engine
		autoload :Buffer, 'cryptcheck/engine/buffer'
		autoload :CountableBuffer, 'cryptcheck/engine/countable_buffer'
	end
end

fixtures = File.join __dir__, 'engine/fixtures/*.rb'
Dir[fixtures].each { |f| load f }

module Cryptcheck
	module Engine
		autoload :Error, 'cryptcheck/engine/error'
		autoload :DoubleHash, 'cryptcheck/engine/double_hash'
		autoload :IdClasses, 'cryptcheck/engine/id_classes'
		autoload :Tls, 'cryptcheck/engine/tls'
	end
end
