require 'securerandom'

module Cryptcheck::Engine
	module Tls
		class Handshake
			class ClientHello
				ID = 0x01

				def self.read(io)
					read    = 0
					r, tmp  = io.read_uint16
					read    += r
					version = VERSIONS[tmp]
					raise ProtocolError, "Unknown client version 0x#{tmp.to_s 16}" unless version

					r      = 32
					random = io.read r
					read   += r

					r, session = io.read_data :uint8
					read       += r

					r, ciphers = read_ciphers io
					read       += r

					r, compressions = read_compressions io
					read            += r

					r, extensions = read_extensions io
					read          += r

					record = self.new version, random, session, ciphers, compressions, extensions
					[read, record]
				end

				def write(io)
					written = 0
					version = VERSIONS.inverse @version
					written += io.write_uint16 version
					written += io.write @random
					written += io.write_data :uint8, @session
					written += write_ciphers io
					written += write_compressions io
					written += write_extensions io
					written
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

				def self.read_ciphers(io)
					read       = 0
					r, length  = io.read_uint16
					read       += r
					r, ciphers = io.collect length do
						r, tmp = io.read_uint16
						cipher = CIPHERS[tmp]
						raise ProtocolError, 'Unknown cipher 0x%04X' % tmp unless cipher
						[r, cipher]
					end
					read       += r
					[read, ciphers]
				end

				def write_ciphers(io)
					io2 = StringIO.new
					@ciphers.each do |c|
						c = CIPHERS.inverse c
						io2.write_uint16 c
					end
					io.write_data :uint16, io2.string
				end

				def self.read_compressions(io)
					read            = 0
					r, length       = io.read_uint8
					read            += r
					r, compressions = io.collect length do
						r, tmp      = io.read_uint8
						compression = COMPRESSIONS[tmp]
						raise ProtocolError, 'Unknown compression 0x%02X' % tmp unless compression
						[r, compression]
					end
					read            += r
					[read, compressions]
				end

				def write_compressions(io)
					io2 = StringIO.new
					@compressions.each do |c|
						c = COMPRESSIONS.inverse c
						io2.write_uint8 c
					end
					io.write_data :uint8, io2.string
				end

				def self.read_extensions(io)
					read          = 0
					r, length     = io.read_uint16
					read          += r
					r, extensions = io.collect length do
						r, extension = Extension.read io
						[r, extension]
					end
					read          += r
					[read, extensions]
				end

				def write_extensions(io)
					io2 = StringIO.new
					@extensions.each { |e| Extension.write io2, e }
					io.write_data :uint16, io2.string
				end

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
