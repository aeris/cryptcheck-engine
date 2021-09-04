lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cryptcheck/engine/version'

Gem::Specification.new do |spec|
  spec.name    = 'cryptcheck-engine'
  spec.version = Cryptcheck::Engine::VERSION
  spec.authors = %w[aeris]
  spec.email   = %w[aeris@imirhil.fr]
  spec.license = 'AGPL-3.0-or-later'

  spec.summary     = %q{Pure ruby SSL/TLS engine}
  spec.description = <<-EOF
    Pure ruby SSL/TLS engine.
    This engine is design to test server handshake without relying on OpenSSL,
    and so to include together deprecated and newest SSL/TLS protocols, cipher
    suites and features.

    /!\ DON'T USE IT IN PRODUCTION /!\
    This is not a cryptographic safe implementation!
  EOF
  spec.homepage = 'https://git.imirhil.fr/aeris/cryptcheck-engine/'

  spec.files         = %w(README.md) + Dir.glob('lib/**/*', base: __dir__)
  spec.bindir        = File.expand_path('..', __FILE__)
  spec.executables   = Dir.glob('bin/**/*', base: File.join(__dir__, spec.bindir))
  spec.require_paths = %w[lib]
  spec.test_files    = Dir.glob('spec/**/*', base: __dir__)

  spec.add_development_dependency 'bundler', '~> 2.2.0'
  spec.add_development_dependency 'rake', '~> 13.0.6'
  spec.add_development_dependency 'pry', '~> 0.13.1'
  spec.add_development_dependency 'amazing_print', '~> 1.3.0'
end
