require 'rspec/expectations'

RSpec::Matchers.define :eq_hex do |expected|
	attr_reader :actual, :expected
	match do |actual|
		expected           = expected.from_hex
		actual             = actual.b
		@actual, @expected = diff_hex actual, expected
		values_match? expected, actual
	end
	diffable
end
