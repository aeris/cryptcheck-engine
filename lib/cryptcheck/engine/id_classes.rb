module Cryptcheck::Engine
	class IdClasses < DoubleHash
		def initialize(*classes)
			super classes.collect { |c| [c::ID, c] }.to_h
		end
	end
end
