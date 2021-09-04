module Cryptcheck::Engine
  module Tls
    class Application
      ID = 0x17

      attr_reader :data

      def initialize(data)
        @data = data
      end

      def self.read(_, io, length)
        data = io.read length
        self.new data
      end

      def write(_, io)
        io.write self.data
      end
    end
  end
end
