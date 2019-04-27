require 'rspec/expectations'

RSpec::Matchers.define :eq_hex do |expected|
	attr_reader :actual, :expected
	match do |actual|
		tmp       = actual.to_hex.upcase
		n         = 0
		@expected = expected.upcase
		@actual   = @expected.each_char.collect do |e|
			unless e =~ /\s/
				t = tmp[n]
				e = t if t
				n += 1
			end
			e
		end.join
		tmp       = tmp[n..-1]
		@actual   += tmp if tmp
		values_match? expected.from_hex, actual.b
	end
	# failure_message do |actual|
	# 	expected = expected.gsub(/\s/, '').upcase
	# 	"expected \"#{actual.to_hex}\" to eq hex \"#{expected}\""
	# end
	diffable
end
