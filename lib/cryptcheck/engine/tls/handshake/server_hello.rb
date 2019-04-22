require 'securerandom'

module Cryptcheck::Engine
	module Tls
		class Handshake
			class ServerHello
				ID = 0x02

				def self.read(io)
					read       = 0
					r, version = Tls.read_version io
					read       += r

					r      = 32
					random = io.read r
					read   += r

					r, session = io.read_data :uint8
					read       += r

					r, cipher = Tls.read_cipher io
					read      += r

					r, compression = Tls.read_compression io
					read           += r

					r, extensions = Extension.read_all io
					read          += r

					record = self.new version, random, session, cipher, compression, extensions
					[read, record]
				end

				def write(io)
					written = 0
					written += Tls.write_version io, @version
					written += io.write @random
					written += io.write_data :uint8, @session
					written += Tls.write_cipher io, @cipher
					written += Tls.write_compression io, @compression
					written += Extension.write_all io, @extensions
					written
				end

				attr_reader :version, :random, :session, :cipher, :compression, :extensions

				def initialize(version, random, session, cipher, compression, extensions)
					@version     = version
					@random      = random
					@session     = session
					@cipher      = cipher
					@compression = compression
					@extensions  = extensions
				end

				private

				class Builder
					def initialize
						@compression = :NULL
						@extensions  = []
					end

					def get
						@random ||= SecureRandom.bytes 32
						ServerHello.new @version, @random, @session, @cipher, @compression, @extensions
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

					def cipher(cipher)
						@cipher = cipher
						self
					end

					def compression(compression)
						@compression = compression
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
