module Cryptcheck::Engine
	module Tls
		class Handshake
			class Certificate
				ID = 0x0B

				def self.read(_, io)
					length = io.read_uint 3
					certs  = io.collect length do
						der = io.read_data 3
						OpenSSL::X509::Certificate.new der
					end
					self.new certs
				end

				def write(_, io)
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
