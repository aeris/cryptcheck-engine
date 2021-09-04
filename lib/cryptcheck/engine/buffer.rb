module Cryptcheck::Engine
  module Buffer
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
				data.unpack('#{type}').first
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
        value += self.read_uint8
      end
      value
    end

    def write_uint(size, value)
      value = size.times.collect { t = value % 0x0100; value /= 0x0100; t }.reverse
      value.each { |s| self.write_uint8 s }
      size
    end

    def read_data(type)
      length =
        case type
        when Symbol
          self.send "read_#{type}"
        else
          self.read_uint type
        end
      data   = if length == 0
                 nil
               else
                 data = self.read length
                 size = data.size
                 raise EOFError, "Unable to read #{length} bytes, #{size} bytes read" unless size == length
                 data.b
               end
      data
    end

    def write_data(type, data)
      data ||= ''
      data = data.b
      size = data.size
      case type
      when Symbol
        self.send "write_#{type}", size
      else
        self.write_uint type, size
      end
      self.write data
    end

    def collect(length, &block)
      CountableBuffer.collect self, length, &block
    end

    def reads(&block)
      CountableBuffer.reads self, &block
    end

    def writes(&block)
      CountableBuffer.writes self, &block
    end

    def reads_writes(&block)
      CountableBuffer.reads_writes self, &block
    end
  end
end
