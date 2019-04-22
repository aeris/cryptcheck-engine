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
			def read_#{name}
				data = self.read #{size}
				data = data.unpack('#{type}').first
				[#{size}, data]
			end

			def write_#{name}(value)
				data = [value].pack '#{type}'
				self.write data
			end
		RUBY_EVAL

		def write_data(type, data)
			data    ||= ''
			data    = data.b
			written = 0
			size    = data.size
			written += self.send "write_#{type}", size
			written += self.write data
			written
		end

		def read_data(type)
			read      = 0
			r, length = self.send "read_#{type}"
			read      += r
			data      = if length == 0
							nil
						else
							data = self.read length
							read += length
							data.b
						end
			[read, data]
		end
	end

	def collect(length)
		results, read = [], 0
		loop do
			r, result = yield
			results << result
			read += r
			break unless read < length
		end
		[read, results]
	end
end
