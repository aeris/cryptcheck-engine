require 'securerandom'

module Cryptcheck::Engine
	module Tls
		class Handshake
			class ClientHello
				ID = 0x01

				def self.read(io)
					version      = Tls.read_version io
					random       = io.read 32
					session      = io.read_data :uint8
					ciphers      = Tls.read_ciphers io
					compressions = Tls.read_compressions io
					extensions   = Extension.read_all io
					self.new version, random, session, ciphers, compressions, extensions
				end

				def write(io)
					Tls.write_version io, @version
					io.write @random
					io.write_data :uint8, @session
					Tls.write_ciphers io, @ciphers
					Tls.write_compressions io, @compressions
					Extension.write_all io, @extensions
				end

				attr_reader :version, :random, :session, :ciphers, :compressions, :extensions

				def initialize(version, random, session, ciphers, compressions, extensions)
					@version      = version
					@random       = random
					@session      = session
					@ciphers      = ciphers
					@compressions = compressions
					@extensions   = extensions
				end

				private


				class Builder
					def initialize
						@ciphers      = []
						@compressions = %i[NULL]
						@extensions   = []
					end

					def get
						@random ||= SecureRandom.bytes 32
						ClientHello.new @version, @random, @session, @ciphers, @compressions, @extensions
					end

					def version(version)
						@version = version
						self
					end

					def random(random)
						@random = random
						self
					end

					def session(session)
						@session = session
						self
					end

					def ciphers(ciphers)
						@ciphers += ciphers
						self
					end

					def cipher(cipher)
						@ciphers << cipher
						self
					end

					def compressions(compressions)
						@compressions += compressions
						self
					end

					def compression(compression)
						@compression < compression
						self
					end

					def extensions(extensions)
						@extensions += extensions
						self
					end

					def extension(extension)
						@extensions << extension
						self
					end
				end

				def self.build(&block)
					builder = Builder.new
					builder.instance_eval &block if block_given?
					builder.get
				end
			end
		end
	end
end
