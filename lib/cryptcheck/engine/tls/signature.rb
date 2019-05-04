module Cryptcheck::Engine
	module Tls
		class Signature
			def self.read_scheme(io)
				read, tmp = io.read_uint16
				scheme    = SIGNATURE_SCHEMES[tmp]
				raise ProtocolError, 'Unknown signature scheme 0x%04X' % tmp unless scheme
				[read, scheme]
			end

			def self.read_schemes(io)
				io.collect(:uint16) { self.read_scheme io }
			end

			def self.write_scheme(io, scheme)
				id = SIGNATURE_SCHEMES.inverse scheme
				raise ProtocolError, 'Unknown signature scheme %s' % scheme unless id
				io.write_uint16 id
			end

			def self.write_schemes(io, schemes)
				io2 = StringIO.new
				schemes.each { |s| self.write_scheme io2, s }
				io.write_data :uint16, io2.string
			end

			def self.read(io)
				read         = 0
				r, scheme    = self.read_scheme io
				read         += r
				r, signature = io.read_data :uint16
				read         += r
				signature    = self.new scheme, signature
				[read, signature]
			end

			def write(io)
				written = 0
				written += self.class.write_scheme io, @scheme
				written += io.write_data :uint16, @signature
				written
			end

			attr_reader :scheme, :signature

			def initialize(scheme, signature)
				@scheme    = scheme
				@signature = signature
			end
		end
	end
end
