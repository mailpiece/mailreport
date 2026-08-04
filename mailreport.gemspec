$LOAD_PATH.push File.expand_path('lib', __dir__)
require_relative "lib/mailreport/version"

Gem::Specification.new do |spec|
  spec.name = "mailreport"
  spec.version = MailReport::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "DMARC report parsing for Ruby."
  spec.description = "DMARC report parsing for Ruby. Reads the reports receivers send back about your domain — how your mail performed on their end."

  spec.homepage = "https://github.com/mailpiece/mailreport"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Dir, not `git ls-files`: an uncommitted checkout would package an empty gem.
  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "mailreport.gemspec"
  ]
  spec.require_paths = [ "lib" ]

  # CVE-2024-43398 (DoS, fixed 3.3.6); CVE-2024-49761 (ReDoS, fixed 3.3.9;
  # Ruby 3.1-only in practice — we require >= 3.3.4).
  spec.add_dependency "rexml", ">= 3.3.9"
  spec.add_dependency "zip_kit", "~> 6.3"
end
