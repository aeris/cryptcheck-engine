module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerKeyExchange
				ID = 0x0C
			end

			class EcdhServerKeyExchange < ServerKeyExchange
				def self.read(io)
					read = 0

					r, curve_type = Tls.read_curve_type io
					read          += r
					raise 'Unsupported curve type' unless curve_type == :named_curve

					case curve_type
					when :named_curve
						r, group      = Tls.read_group io
						read          += r
						r, public_key = io.read_data :uint8
						read          += r
					end
					r, signature = Signature.read io
					read         += r

					ecdh = self.new group, public_key, signature
					[read, ecdh]
				end

				def write(io)
					written = 0
					written += Tls.write_curve_type io,:named_curve
					written += Tls.write_group io, @group
					written += io.write_data :uint8, @public_key
					written += @signature.write io
					written
				end

				attr_reader :group, :public_key, :signature

				def initialize(group, public_key, signature)
					@group      = group
					@public_key = public_key
					@signature  = signature
				end
			end

			class DhServerKeyExchange < ServerKeyExchange
				def self.read(io)
					read = 0

					r, p  = io.read_data :uint16
					read  += r
					r, g  = io.read_data :uint16
					read  += r
					r, ys = io.read_data :uint16
					read  += r

					r, signature = Signature.read io
					read         += r

					dh = self.new p, g, ys, signature
					[read, dh]
				end

				def write(io)
					written = 0
					written += io.write_data :uint16, @p
					written += io.write_data :uint16, @g
					written += io.write_data :uint16, @ys
					written += @signature.write io
					written
				end

				attr_reader :p, :g, :ys, :signature

				def initialize(p, g, ys, signature)
					@p         = p
					@g         = g
					@ys        = ys
					@signature = signature
				end
			end
		end
	end
end
