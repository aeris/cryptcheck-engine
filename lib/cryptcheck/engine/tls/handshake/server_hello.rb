require 'securerandom'

module Cryptcheck::Engine
  module Tls
    class Handshake
      class ServerHello
        ID = 0x02

        def self.read(_, io)
          version     = Tls.read_version io
          random      = io.read 32
          session     = io.read_data :uint8
          cipher      = Tls.read_cipher io
          compression = Tls.read_compression io
          extensions  = Extension.read_all io
          self.new version, random, session, cipher, compression, extensions
        end

        def write(_, io)
          Tls.write_version io, @version
          io.write @random
          io.write_data :uint8, @session
          Tls.write_cipher io, @cipher
          Tls.write_compression io, @compression
          Extension.write_all io, @extensions
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

        class Builder_
          include Builder
          attributes :version, :random, :session, :cipher, :compression
          lists :extension

          def initialize
            @compression = :NULL
            @extensions  = []
          end

          def get
            @random ||= SecureRandom.bytes 32
            ServerHello.new @version, @random, @session, @cipher, @compression, @extensions
          end
        end

        def self.build(&block)
          builder = Builder_.new
          builder.instance_eval &block if block_given?
          builder.get
        end
      end
    end
  end
end
