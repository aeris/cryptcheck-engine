require 'rspec/expectations'

def expect_to_be_read_and_written_bytes(io, expected_read = 0, expected_data = '')
  read, written = io.count
  expect(read).to eq(expected_read), "#{read} bytes read, #{expected_read} expected"
  expected_written = expected_data.size
  expect(written).to eq(expected_written), "#{written} bytes read, #{expected_written} expected"
end

def expect_to_be_read_and_written(io, expected_read = 0, expected_data = '')
  expect_to_be_read_and_written_bytes io, expected_read, expected_data
  data = io.string
  expect(data).to eq expected_data
end

def expect_to_be_hex_read_and_written(io, expected_read = 0, expected_data = '')
  expect_to_be_read_and_written_bytes io, expected_read, expected_data.from_hex
  data = io.string
  expect(data).to eq_hex expected_data
end

def diff_hex(actual, expected)
  tmp      = actual.to_hex.upcase
  n        = 0
  expected = expected.upcase
  actual   = expected.each_char.collect do |e|
    unless e =~ /\s/
      t = tmp[n]
      e = t if t
      n += 1
    end
    e
  end.join
  tmp      = tmp[n..-1]
  actual   += tmp if tmp
  [actual, expected]
end

RSpec::Matchers.define :be_read do |expected|
  match do |actual|
    expect_to_be_read_and_written_bytes actual, expected
  end
end

RSpec::Matchers.define :be_written do |expected|
  match do |actual|
    expect_to_be_read_and_written actual, 0, expected
  end
  diffable
end

RSpec::Matchers.define :be_hex_written do |expected|
  match do |actual|
    @actual, @expected = diff_hex actual.string, expected
    expect_to_be_hex_read_and_written actual, 0, expected
  end
  diffable
  attr_reader :actual, :expected
end
