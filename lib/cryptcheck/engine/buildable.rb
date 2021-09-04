module Cryptcheck::Engine
  module Buildable
    def self.included(klass)
      klass.extend ClassMethod
    end

    private

    module ClassMethod
      def buildable(&block)
        @@builder = Class.new do
          include Builder
        end
        @@builder.instance_eval &block if block_given?
      end

      def build(&block)
        builder = @@builder.new
        builder.instance_eval &block if block_given?
        builder.resolve
      end
    end
  end
end
