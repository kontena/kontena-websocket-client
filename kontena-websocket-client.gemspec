# coding: utf-8
Gem::Specification.new do |spec|
  spec.name          = "kontena-websocket-client"
  spec.version       = '0.1.1'
  spec.authors       = ["Kontena, Inc"]
  spec.email         = ["info@kontena.io"]

  spec.summary       = %q{Websocket client library}
  spec.homepage      = "https://github.com/kontena/kontena-websocket-client"
  spec.license       = "Apache-2.0"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "websocket-driver", '~> 0.6.5'

  spec.add_development_dependency "bundler", "~> 1.15"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
