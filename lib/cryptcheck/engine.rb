require 'cryptcheck/engine/version'

fixtures = File.join __dir__, 'engine/fixtures/*.rb'
Dir[fixtures].each { |f| require f }

module Cryptcheck
	module Engine
		class Error < StandardError;
		end
	end
end
