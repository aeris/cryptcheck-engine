module Cryptcheck::Engine
	module Tls
		class Handshake
			class Certificate
				ID = 0x0B

				def self.read(io)
					read      = 0
					r, length = io.read_uint 3
					read      += r

					r, certs = io.collect length do
						r, der = io.read_data 3
						cert   = OpenSSL::X509::Certificate.new der
						[r, cert]
					end
					read     += r

					certs = self.new certs
					[read, certs]
				end

				def write(io)
					io2 = StringIO.new
					@certificates.each { |c| io2.write_data 3, c.to_der }
					io.write_data 3, io2.string
				end

				attr_reader :certificates

				def initialize(certificates)
					@certificates = certificates
				end
			end
		end
	end
end
