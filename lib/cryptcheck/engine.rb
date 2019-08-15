require 'cryptcheck/engine/version'

module Cryptcheck::Engine
	autoload :Buffer, 'cryptcheck/engine/buffer'
	autoload :CountableBuffer, 'cryptcheck/engine/countable_buffer'

	fixtures = File.join __dir__, 'engine/fixtures/*.rb'
	Dir[fixtures].each { |f| load f }

	autoload :Builder, 'cryptcheck/engine/builder'
	autoload :Error, 'cryptcheck/engine/error'
	autoload :DoubleHash, 'cryptcheck/engine/double_hash'
	autoload :IdClasses, 'cryptcheck/engine/id_classes'
	autoload :Tls, 'cryptcheck/engine/tls'
end
