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
	end

	def read_uint(size)
		value = 0
		size.times do
			value *= 0x0100
			_, t  = self.read_uint8
			value += t
		end
		[size, value]
	end

	def write_uint(size, value)
		value = size.times.collect { t = value % 0x0100; value /= 0x0100; t }.reverse
		value.each { |s| self.write_uint8 s }
		size
	end

	def write_data(type, data)
		data    ||= ''
		data    = data.b
		written = 0
		size    = data.size
		written += case type
				   when Symbol
					   self.send "write_#{type}", size
				   else
					   self.write_uint type, size
				   end
		written += self.write data
		written
	end

	def read_data(type)
		read      = 0
		r, length =
				case type
				when Symbol
					self.send "read_#{type}"
				else
					self.read_uint type
				end
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

	def collect(length)
		results, read = [], 0

		if length.is_a? Symbol
			r, l   = self.send "read_#{length}"
			read   += r
			length = l
		end

		pos = 0
		loop do
			r, result = yield
			results << result
			read += r
			pos  += r
			break unless pos < length
		end

		[read, results]
	end
end
