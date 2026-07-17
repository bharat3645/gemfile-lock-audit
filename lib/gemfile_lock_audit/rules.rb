# frozen_string_literal: true

module GemfileLockAudit
  Finding = Struct.new(:rule_id, :severity, :subject, :message, keyword_init: true)

  SEVERITY_WEIGHTS = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0
  }.freeze

  # The remote Bundler talks to unless a Gemfile source overrides it. Any GEM
  # section remote other than this is a deliberate choice (private gem
  # server, internal mirror, etc.) -- not wrong, but worth surfacing.
  DEFAULT_GEM_REMOTE = "https://rubygems.org/"

  # A curated list of well-known, high-traffic RubyGems used only for the
  # typosquat heuristic below. Not exhaustive, not a trust allowlist -- just
  # a reference set of names an attacker would plausibly want to impersonate.
  WELL_KNOWN_GEMS = %w[
    rails railties activesupport activerecord actionpack actionview
    actionmailer actioncable activejob activestorage
    rake rspec rspec-rails minitest bundler
    devise sidekiq puma nokogiri faraday httparty pg mysql2 redis
    sinatra thor rubocop capybara factory_bot faker jbuilder kaminari
    pundit omniauth resque delayed_job aws-sdk stripe twilio-ruby
    jwt bcrypt warden rack rack-cors listen spring sprockets i18n
    mail nokogiri loofah sanitize graphql webpacker
  ].freeze

  module Rules
    module_function

    # Every rule takes a GemfileLockAudit::Lockfile and returns an Array[Finding].

    def git_branch_source(lockfile)
      lockfile.git_sources.filter_map do |src|
        next unless src.branch && !src.tag && !src.ref

        Finding.new(
          rule_id: "GIT_TRACKS_BRANCH",
          severity: :high,
          subject: src.remote || "(unknown remote)",
          message: "Git source #{src.remote.inspect} tracks branch '#{src.branch}' " \
                    "instead of a fixed tag or ref. The lockfile pins a specific " \
                    "revision today, but the next `bundle update` will follow " \
                    "whatever that branch has become -- including commits nobody " \
                    "on this project has reviewed."
        )
      end
    end

    def git_source_present(lockfile)
      lockfile.git_sources.filter_map do |src|
        next unless src.remote

        Finding.new(
          rule_id: "GIT_SOURCE",
          severity: :medium,
          subject: src.remote,
          message: "Gem(s) #{src.gems.map(&:name).join(', ')} are sourced directly " \
                    "from git (#{src.remote}) rather than a package registry. " \
                    "There's no publish/yank/signing step in between -- whatever is " \
                    "at that revision is what ships."
        )
      end
    end

    def path_source_present(lockfile)
      lockfile.path_sources.filter_map do |src|
        Finding.new(
          rule_id: "PATH_SOURCE",
          severity: :info,
          subject: src.remote || "(local path)",
          message: "Gem(s) #{src.gems.map(&:name).join(', ')} are loaded from a local " \
                    "path (#{src.remote}). Harmless for local development, but this " \
                    "lockfile won't resolve as-is on another machine or in CI unless " \
                    "that path also exists there."
        )
      end
    end

    def unconstrained_dependency(lockfile)
      lockfile.dependencies.filter_map do |dep|
        next if dep[:constraint] && !dep[:constraint].strip.empty?

        Finding.new(
          rule_id: "UNCONSTRAINED_DEPENDENCY",
          severity: :info,
          subject: dep[:name],
          message: "'#{dep[:name]}' has no version constraint in the Gemfile at all. " \
                    "The next `bundle update` is free to jump it to any version, " \
                    "including a new major with breaking changes."
        )
      end
    end

    def prerelease_pin(lockfile)
      lockfile.gem_specs.values.filter_map do |spec|
        next unless spec.version =~ /[a-zA-Z]/ # e.g. 1.2.3.pre, 2.0.0.rc1, 3.0.0.beta

        Finding.new(
          rule_id: "PRERELEASE_PIN",
          severity: :low,
          subject: spec.name,
          message: "'#{spec.name}' is locked to #{spec.version}, which looks like a " \
                    "pre-release build (alpha/beta/rc/pre). Worth confirming that's " \
                    "intentional and not a leftover from local testing."
        )
      end
    end

    def missing_bundled_with(lockfile)
      return [] if lockfile.bundled_with

      [Finding.new(
        rule_id: "MISSING_BUNDLED_WITH",
        severity: :info,
        subject: "(lockfile)",
        message: "No 'BUNDLED WITH' section -- the Bundler version used to resolve " \
                  "this lockfile isn't pinned, so different machines/CI runners could " \
                  "resolve dependencies slightly differently over time."
      )]
    end

    def custom_gem_remote(lockfile)
      lockfile.gem_remotes.uniq.filter_map do |remote|
        next if remote == DEFAULT_GEM_REMOTE

        Finding.new(
          rule_id: "CUSTOM_GEM_REMOTE",
          severity: :medium,
          subject: remote,
          message: "Gems are resolved from #{remote.inspect} instead of the default " \
                    "#{DEFAULT_GEM_REMOTE.inspect}. This is normal for a private gem " \
                    "server or mirror, but it also means rubygems.org's yank/ownership " \
                    "checks don't apply -- worth confirming this remote is one your " \
                    "team actually controls and trusts."
        )
      end
    end

    def possible_typosquat(lockfile)
      names = lockfile.gem_specs.keys
      names.filter_map do |name|
        next if WELL_KNOWN_GEMS.include?(name)

        near = WELL_KNOWN_GEMS.find { |known| close_but_not_equal?(name, known) }
        next unless near

        Finding.new(
          rule_id: "POSSIBLE_TYPOSQUAT",
          severity: :high,
          subject: name,
          message: "'#{name}' is suspiciously similar to the well-known gem " \
                    "'#{near}' but not identical -- worth a manual check that this " \
                    "isn't a typosquat before trusting it."
        )
      end
    end

    def close_but_not_equal?(a, b)
      return false if a == b
      return false if (a.length - b.length).abs > 2

      levenshtein(a, b) <= 2
    end

    def levenshtein(a, b)
      m, n = a.length, b.length
      return n if m.zero?
      return m if n.zero?

      d = Array.new(m + 1) { Array.new(n + 1, 0) }
      (0..m).each { |i| d[i][0] = i }
      (0..n).each { |j| d[0][j] = j }

      (1..m).each do |i|
        (1..n).each do |j|
          cost = a[i - 1] == b[j - 1] ? 0 : 1
          d[i][j] = [
            d[i - 1][j] + 1,
            d[i][j - 1] + 1,
            d[i - 1][j - 1] + cost
          ].min
        end
      end

      d[m][n]
    end

    ALL = %i[
      git_branch_source
      git_source_present
      path_source_present
      unconstrained_dependency
      prerelease_pin
      missing_bundled_with
      custom_gem_remote
      possible_typosquat
    ].freeze
  end
end
