require 'cryptcheck/engine/version'

fixtures = File.join __dir__, 'engine/fixtures/*.rb'
Dir[fixtures].each { |f| require f }

module Cryptcheck
	module Engine
		autoload :Error, 'cryptcheck/engine/error'
		autoload :DoubleHash, 'cryptcheck/engine/double_hash'
		autoload :IdClasses, 'cryptcheck/engine/id_classes'
		autoload :Tls, 'cryptcheck/engine/tls'
	end
end
