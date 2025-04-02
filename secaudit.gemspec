# secaudit.gemspec

Gem::Specification.new do |spec|
  spec.name          = "secaudit"
  spec.version       = Secaudit::VERSION
  spec.summary       = "PhantomRecon Web Security Scanner"
  spec.description   = "CLI tool for SSL, HTTP headers, DNSSEC, CAA, and CDN auditing"
  spec.authors       = ["Daniel J. Monbrod"]
  spec.email         = ["dmonbr53@outlook.com"]

  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6"

  spec.files         = Dir["lib/**/*.rb"] + ["bin/secaudit", "LICENSE", "README.md"]
  spec.executables   = ["secaudit"]
  spec.bindir        = "bin"
  spec.require_paths = ["lib"]

  spec.add_dependency "thor"
  spec.add_dependency "concurrent-ruby"
  spec.add_dependency "dnsruby", require: false
  spec.add_dependency "rubyzip"
end
