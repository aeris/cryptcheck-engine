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

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = %w[lib]

  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'pry', '~> 0.12.2'
  spec.add_development_dependency 'awesome_print', '~> 1.8.0'
end
