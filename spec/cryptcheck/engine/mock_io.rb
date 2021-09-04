module Cryptcheck::Engine
  class MockIO < CountableBuffer
    def initialize
      @io = StringIO.new
      super @io
    end

    def init(string = '')
      @io.string = string.from_hex
    end

    def string
      @io.string
    end
  end
end
