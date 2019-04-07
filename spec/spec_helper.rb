require 'bundler/setup'

Dir[File.join __dir__, 'fixtures', '*.rb'].each { |file| require file }

require 'cryptcheck/engine'
require 'cryptcheck/engine/mock_io'

require 'awesome_print'
require 'colorize'
require 'pry-byebug'
require 'simplecov'
SimpleCov.start do
	add_filter 'spec/'
end

require './spec/helpers'
RSpec.configure do |config|
	config.include Helpers

	# Enable flags like --only-failures and --next-failure
	config.example_status_persistence_file_path = '.rspec_status'

	# Disable RSpec exposing methods globally on `Module` and `main`
	config.disable_monkey_patching!

	config.expect_with :rspec do |c|
		c.syntax = :expect
	end
end

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

