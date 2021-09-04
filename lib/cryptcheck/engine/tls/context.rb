module Cryptcheck::Engine
  module Tls
    class Context
      include Buildable
      buildable do
        attributes :ip, :port, :hostname, :version
        lists :compression, :cipher
        build do
          client = Client.new @ip, @port, @hostname, @version, @compressions, @cipher
          Context.new client
        end
      end

      attr_reader :server, :client

      private

      def initialize(client)
        @client = client
        @server = Server.new
      end

      class Client
        attr_accessor :random

        def initialize(ip, port, hostname, version, compressions, ciphers)
          @ip           = ip
          @port         = port
          @hostname     = hostname
          @version      = version
          @compressions = compressions
          @ciphers      = ciphers
        end
      end

      class Server
      end
    end
  end
end
