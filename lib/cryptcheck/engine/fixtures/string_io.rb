require 'stringio'

class StringIO
	{
			uint8:  [1, 'C'],
			uint16: [2, 'S>'],
			uint32: [4, 'L>'],
			uint64: [8, 'Q>'],

			int8:   [1, 'c'],
			int16:  [2, 's>'],
			int32:  [4, 'l>'],
			int64:  [8, 'q>'],
	}.each do |name, config|
		size, type = config
		class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
			def read_#{name}(*args, **kwargs)
				data = self.read #{size}, *args, **kwargs
				data.unpack('#{type}').first
			end
		RUBY_EVAL
	end
end
