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

    # CUSTOM_GEM_REMOTE (above) says "a non-default remote exists somewhere in
    # this lockfile". It can't say more than that because gem_specs used to
    # discard which GEM block (and therefore which remote) each spec came
    # from. Now that Parser attaches the originating remote to every
    # rubygems-sourced GemSpec, this rule names the specific gem(s) -- the
    # per-gem attribution a scoped `source "..." do ... end` block in the
    # Gemfile produces. Severity :info: it's detail on a risk CUSTOM_GEM_REMOTE
    # already scored, not a second independent one, so it doesn't add to the
    # point deduction.
    def custom_source_dependency(lockfile)
      lockfile.gem_specs.values.filter_map do |spec|
        next unless spec.source == :rubygems
        next unless spec.remote
        next if spec.remote == DEFAULT_GEM_REMOTE

        Finding.new(
          rule_id: "CUSTOM_SOURCE_DEPENDENCY",
          severity: :info,
          subject: spec.name,
          message: "'#{spec.name}' (#{spec.version}) resolves from #{spec.remote.inspect} " \
                    "rather than the default #{DEFAULT_GEM_REMOTE.inspect} -- likely pinned " \
                    "there by a scoped `source \"...\" do ... end` block in the Gemfile. " \
                    "See CUSTOM_GEM_REMOTE for the remote-level finding; this is the " \
                    "gem-level detail so you know exactly which dependency it applies to."
        )
      end
    end

    # Bundler appends "!" to a DEPENDENCIES entry exactly when that gem needs
    # a pinned, non-default source to resolve -- GIT, PATH, or a scoped
    # `source "..." do ... end` custom GEM remote (see CUSTOM_SOURCE_DEPENDENCY
    # above). A clean `bundle lock` never disagrees with itself about this;
    # a hand edit or a bad merge conflict resolution can, e.g. a gem moved
    # into a custom GEM block without adding "!" in DEPENDENCIES, or a stray
    # "!" left over after a gem was moved back to the default source. Either
    # direction of disagreement means the lockfile no longer accurately
    # describes where a gem actually comes from. Severity :medium, same as
    # GIT_SOURCE/CUSTOM_GEM_REMOTE: it's a real integrity problem with the
    # lockfile, not just supplementary detail.
    def source_pin_mismatch(lockfile)
      git_gems = lockfile.git_sources.flat_map { |src| src.gems.map(&:name) }
      path_gems = lockfile.path_sources.flat_map { |src| src.gems.map(&:name) }

      lockfile.dependencies.filter_map do |dep|
        name = dep[:name]
        spec = lockfile.gem_specs[name]

        pinned_source =
          if git_gems.include?(name) || path_gems.include?(name)
            true
          elsif spec
            !spec.remote.nil? && spec.remote != DEFAULT_GEM_REMOTE
          end

        # Gem isn't in GIT, PATH, or GEM at all (an incomplete/corrupt
        # lockfile) -- nothing to cross-check it against.
        next if pinned_source.nil?
        next if pinned_source == dep[:pinned]

        Finding.new(
          rule_id: "SOURCE_PIN_MISMATCH",
          severity: :medium,
          subject: name,
          message: if dep[:pinned]
                     "'#{name}' is marked '!' in DEPENDENCIES (pinned to a specific " \
                     "source) but resolves from the default rubygems remote in GEM. " \
                     "Bundler only adds '!' for git/path/custom-remote gems -- this " \
                     "looks like a stray bang left over from a hand edit or merge."
                   else
                     "'#{name}' resolves from a non-default source (git, path, or a " \
                     "custom GEM remote) but isn't marked '!' in DEPENDENCIES. Bundler " \
                     "always pins these with '!' -- a missing bang here suggests a hand " \
                     "edit or a bad merge that left the two sections out of sync."
                   end
        )
      end
    end

    # SOURCE_PIN_MISMATCH (above) cross-checks a DEPENDENCIES entry's "!" bang
    # against where the gem is actually sourced -- but it can only do that when
    # the gem appears in GIT, PATH, or GEM at *some* remote; it explicitly
    # skips (returns nil pinned_source, then `next`) when the gem is missing
    # from all three, since there's nothing to compare the bang against. That
    # skip hides a worse problem than a mismatched bang: a top-level
    # dependency with no spec anywhere means this lockfile cannot actually be
    # installed as-is. A clean `bundle lock` never produces this -- it's the
    # signature of a hand edit, a bad merge conflict resolution that dropped
    # a GEM entry, or a truncated/corrupted file. Severity :high (one step
    # above SOURCE_PIN_MISMATCH's :medium): that rule flags inconsistent
    # metadata on a gem that still resolves; this flags a gem that doesn't
    # resolve at all.
    def dangling_dependency(lockfile)
      git_gems = lockfile.git_sources.flat_map { |src| src.gems.map(&:name) }
      path_gems = lockfile.path_sources.flat_map { |src| src.gems.map(&:name) }

      lockfile.dependencies.filter_map do |dep|
        name = dep[:name]
        next if git_gems.include?(name) || path_gems.include?(name) || lockfile.gem_specs.key?(name)

        Finding.new(
          rule_id: "DANGLING_DEPENDENCY",
          severity: :high,
          subject: name,
          message: "'#{name}' is listed in DEPENDENCIES but has no matching spec in " \
                    "GIT, PATH, or GEM -- this lockfile cannot actually resolve " \
                    "'#{name}'. A clean `bundle lock` never produces this; it points " \
                    "to a hand edit, a bad merge conflict resolution, or a truncated " \
                    "or corrupted lockfile. `bundle install --deployment` (and any " \
                    "frozen/CI install) will fail on this lockfile until it's " \
                    "regenerated with a real `bundle lock`."
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
      custom_source_dependency
      source_pin_mismatch
      dangling_dependency
      possible_typosquat
    ].freeze
  end
end
