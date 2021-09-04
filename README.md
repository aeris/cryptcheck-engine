# Cryptcheck::Engine

CryptCheck needs support of old, unsecured and so deprecated protocols (SSLv2,
SSLv3…) or cipher suite (RC4, 3DES…) to be able to fully cover SSL/TLS
verifications.

OpenSSL 1.0 is necessary to support such deprecated things, but new TLS features
like TLSv1.3 requires 1.2. And currently, Ruby is tied to a single OpenSSL
binding, only old Ruby version (2.3) supports OpenSSL 1.0 and at the opposite,
only 2.5+ supports 1.2.

It will be a real mess to use multiple binding to fully check a server

- multiple OpenSSL bindings
- multiple Ruby versions
- RPC or equivalent
- not totally ordered set for server preferences
- …

This project is a SSL/TLS pure Ruby implementation to remove CryptCheck OpenSSL
dependency and so to support together old and new SSL/TLS features.

__**/!\ DON'T USE IT IN PRODUCTION /!\**__  
This is not a cryptographic safe implementation!

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cryptcheck-engine'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cryptcheck-engine

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake spec` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then
run `bundle exec rake release`, which will create a git tag for the version,
push git commits and tags, and push the `.gem` file
to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub
at https://github.com/aeris/cryptcheck-tls. This project is intended to be a
safe, welcoming space for collaboration, and contributors are expected to adhere
to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Cryptcheck::Engine project’s codebases, issue
trackers, chat rooms and mailing lists is expected to follow
the [code of conduct](https://git.imirhil.fr/aeris/cryptcheck-engine/src/branch/master/CODE_OF_CONDUCT.md)
.
