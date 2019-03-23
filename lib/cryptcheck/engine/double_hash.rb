module Cryptcheck
	module Engine
		class DoubleHash
			def initialize(hash)
				@hash    = hash.freeze
				@inverse = hash.invert.freeze
			end

			def [](key)
				@hash[key]
			end

			def inverse(key)
				@inverse[key]
			end
		end
	end
end
