module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerKeyExchange
				ID = 0x0C
			end

			class EcdhServerKeyExchange < ServerKeyExchange
				def self.read(_, io, anonymous = false)
					curve_type = Tls.read_curve_type io
					raise 'Unsupported curve type' unless curve_type == :named_curve

					case curve_type
					when :named_curve
						group      = Tls.read_group io
						public_key = io.read_data :uint8
					end

					signature = Signature.read io unless anonymous

					self.new group, public_key, signature
				end

				def write(_, io)
					Tls.write_curve_type io, :named_curve
					Tls.write_group io, @group
					io.write_data :uint8, @public_key
					@signature.write io if @signature
				end

				attr_reader :group, :public_key, :signature

				def initialize(group, public_key, signature = nil)
					@group      = group
					@public_key = public_key
					@signature  = signature
				end
			end

			class DhServerKeyExchange < ServerKeyExchange
				def self.read(_, io, anonymous = false)
					p         = io.read_data :uint16
					g         = io.read_data :uint16
					ys        = io.read_data :uint16
					signature = Signature.read io unless anonymous
					self.new p, g, ys, signature
				end

				def write(_, io)
					io.write_data :uint16, @p
					io.write_data :uint16, @g
					io.write_data :uint16, @ys
					@signature.write io if @signature
				end

				attr_reader :p, :g, :ys, :signature

				def initialize(p, g, ys, signature = nil)
					@p         = p
					@g         = g
					@ys        = ys
					@signature = signature
				end
			end
		end
	end
end
