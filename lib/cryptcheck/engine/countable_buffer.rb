module Cryptcheck::Engine
	class CountableBuffer
		include Buffer

		def initialize(io)
			@io   = io
			@read = @written = 0
		end

		def count
			[@read, @written]
		end

		def read(length)
			result = @io.read length
			@read  += result.size
			result
		end

		def write(value)
			written  = @io.write value
			@written += written
			written
		end

		def collect(length)
			length       = self.send "read_#{length}" if length.is_a? Symbol
			results, pos = [], @read
			loop do
				results << yield
				break unless @read - pos < length
			end
			results
		end

		def self.collect(io, length, &block)
			buffer = self.new io
			buffer.collect length, &block
		end

		def self.reads_writes(io, &block)
			buffer        = self.new io
			result        = block.call buffer
			read, written = buffer.count
			[read, written, result]
		end

		def self.reads(io, &block)
			read, _, result = self.reads_writes io, &block
			[read, result]
		end

		def self.writes(io, &block)
			_, written, _ = self.reads_writes io, &block
			written
		end
	end
end
