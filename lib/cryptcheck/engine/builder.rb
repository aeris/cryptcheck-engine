module Cryptcheck::Engine
	module Builder
		def self.included(klass)
			klass.extend ClassMethod
		end

		private

		module ClassMethod
			def attribute(name)
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}(value)
						@#{name} = value
						self
					end
				RUBY_EVAL
			end

			def attributes(*names)
				names.each { |n| self.attribute n }
			end

			def list(name)
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}s(values)
						@#{name}s += values
						self
					end

					def #{name}(value)
						@#{name}s << value
						self
					end
				RUBY_EVAL
			end

			def lists(*names)
				names.each { |n| self.list n }
			end
		end
	end
end
