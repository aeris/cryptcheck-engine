helper = Module.new do
  def klass
    self.described_class
  end
end

RSpec.configure { |c| c.include helper }
