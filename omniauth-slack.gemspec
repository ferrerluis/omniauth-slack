# coding: utf-8
require_relative File.expand_path('../lib/omniauth-slack-v2/version', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-slack-v2'
  spec.version       = Omniauth::SlackV2::VERSION
  spec.authors       = ['Luis Ferrer']
  spec.email         = ['hello@ferrerluis.com']
  spec.description   = %q{OmniAuth strategy for Slack OAuth V2}
  spec.summary       = %q{OmniAuth strategy for Slack OAuth V2}
  spec.homepage      = 'https://github.com/ferrerluis/omniauth-slack.git'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.6'

  spec.add_development_dependency 'bundler', '~> 2.1.4'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'mocha'
end
