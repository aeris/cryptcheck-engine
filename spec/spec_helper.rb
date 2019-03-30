require 'bundler/setup'
require 'cryptcheck/engine'
require 'cryptcheck/engine/mock_socket'

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
	match do |actual|
		expected = Cryptcheck::Engine::MockSocket.from_hex expected
		actual.b == expected.b
	end
end

