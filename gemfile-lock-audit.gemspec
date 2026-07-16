# frozen_string_literal: true

require_relative "lib/gemfile_lock_audit"

Gem::Specification.new do |spec|
  spec.name          = "gemfile-lock-audit"
  spec.version       = GemfileLockAudit::VERSION
  spec.authors       = ["Bharat Singh Parihar"]
  spec.summary       = "Offline supply-chain risk scanner for Gemfile.lock"
  spec.description   = "Grades a Bundler Gemfile.lock A-F on supply-chain risk signals: " \
                        "git sources tracking a floating branch, local path dependencies, " \
                        "unconstrained versions, pre-release pins, missing Bundler pin, " \
                        "and possible gem-name typosquats. Zero runtime dependencies, " \
                        "zero network calls."
  spec.homepage      = "https://github.com/bharat3645/gemfile-lock-audit"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.7"

  spec.files         = Dir["lib/**/*.rb", "bin/*", "README.md", "LICENSE"]
  spec.bindir        = "bin"
  spec.executables   = ["gemfile-lock-audit"]
  spec.require_paths = ["lib"]

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
end
