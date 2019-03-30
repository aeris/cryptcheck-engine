module Cryptcheck
	module Engine
		class DoubleHash
			include Enumerable

			def initialize(hash = {})
				@hash    = hash.freeze
				@inverse = hash.invert.freeze
			end

			def [](key)
				@hash[key]
			end

			def each(&block)
				@hash.each &block
			end

			def inverse(key)
				@inverse[key]
			end
		end
	end
end
