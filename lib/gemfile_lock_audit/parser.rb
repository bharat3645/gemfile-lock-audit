# frozen_string_literal: true

module GemfileLockAudit
  # Raised when a file doesn't look like a Gemfile.lock at all.
  class ParseError < StandardError; end

  # `remote` is only populated for rubygems-sourced specs (nil for :git/:path
  # specs, which already carry their own remote via GitSource/PathSource) --
  # it's the "remote:" line of the specific GEM block this spec's "specs:"
  # list appeared under, so a lockfile with multiple GEM blocks (e.g. from a
  # scoped `source "..." do ... end` in the Gemfile) can attribute each gem
  # to the remote it actually came from, not just the lockfile as a whole.
  GemSpec = Struct.new(:name, :version, :source, :remote, keyword_init: true)
  GitSource = Struct.new(:remote, :revision, :branch, :tag, :ref, :gems, keyword_init: true)
  PathSource = Struct.new(:remote, :gems, keyword_init: true)

  Lockfile = Struct.new(
    :git_sources,      # Array[GitSource]
    :path_sources,     # Array[PathSource]
    :gem_specs,        # Hash[String, GemSpec] -- name => spec, from the GEM section(s)
    :gem_remotes,        # Array[String] -- every "remote:" line seen under a GEM section
    :dependencies,      # Array[{name:, constraint:, pinned:}] -- from the DEPENDENCIES section
                         # (top-level only); pinned is true when the line ended with "!"
    :platforms,         # Array[String]
    :bundled_with,       # String or nil
    :ruby_version,       # String or nil
    keyword_init: true
  )

  # Parses the plain-text Bundler Gemfile.lock format.
  #
  # This is a small, purpose-built parser (not a full Bundler reimplementation).
  # It understands the sections Bundler actually writes: GIT, PATH, GEM,
  # PLATFORMS, DEPENDENCIES, RUBY VERSION, and BUNDLED WITH.
  module Parser
    SECTION_HEADERS = %w[GIT PATH GEM PLATFORMS DEPENDENCIES RUBY\ VERSION BUNDLED\ WITH].freeze

    module_function

    def parse(text)
      lines = text.each_line.map(&:rstrip)
      unless lines.any? { |l| SECTION_HEADERS.include?(l.strip) }
        raise ParseError, "does not look like a Gemfile.lock (no recognized section headers found)"
      end

      git_sources = []
      path_sources = []
      gem_specs = {}
      gem_remotes = []
      dependencies = []
      platforms = []
      bundled_with = nil
      ruby_version = nil

      section = nil
      subsection = nil # within GIT/PATH/GEM: :remote_block, :specs
      current_source = nil # the GitSource/PathSource currently being built
      current_gem_remote = nil # the "remote:" value of the GEM block currently being read

      lines.each do |raw_line|
        next if raw_line.strip.empty?

        indent = raw_line[/\A */].length
        line = raw_line.strip

        if indent.zero?
          section = line
          subsection = nil
          case section
          when "GIT"
            current_source = GitSource.new(gems: [])
            git_sources << current_source
          when "PATH"
            current_source = PathSource.new(gems: [])
            path_sources << current_source
          when "GEM"
            # A lockfile can have more than one top-level GEM block (e.g. one
            # per scoped `source "..." do ... end` in the Gemfile) -- reset so
            # specs in this block aren't attributed to the previous block's
            # remote.
            current_gem_remote = nil
          end
          next
        end

        case section
        when "GIT", "PATH"
          if indent == 2
            key, _, value = line.partition(":")
            value = value.strip
            case key
            when "remote"
              current_source.remote = value
            when "revision"
              current_source.revision = value if current_source.is_a?(GitSource)
            when "branch"
              current_source.branch = value if current_source.is_a?(GitSource)
            when "tag"
              current_source.tag = value if current_source.is_a?(GitSource)
            when "ref"
              current_source.ref = value if current_source.is_a?(GitSource)
            when "specs"
              subsection = :specs
            end
          elsif indent >= 4 && subsection == :specs
            # e.g. "foo (1.2.3)" -- ignore nested transitive deps (deeper indent)
            next if indent > 6
            name, version = parse_spec_line(line)
            current_source.gems << GemSpec.new(name: name, version: version, source: section == "GIT" ? :git : :path) if name
          end
        when "GEM"
          if indent == 2
            key, _, value = line.partition(":")
            key = key.strip
            value = value.strip
            if key == "remote"
              gem_remotes << value unless value.empty?
              current_gem_remote = value unless value.empty?
            elsif key == "specs"
              subsection = :specs
            end
          elsif indent == 4 && subsection == :specs
            name, version = parse_spec_line(line)
            gem_specs[name] = GemSpec.new(name: name, version: version, source: :rubygems, remote: current_gem_remote) if name
          end
          # deeper indents (>4) are transitive sub-dependency listings; not needed for auditing
        when "PLATFORMS"
          platforms << line
        when "DEPENDENCIES"
          name, constraint, pinned = parse_dependency_line(line)
          dependencies << { name: name, constraint: constraint, pinned: pinned } if name
        when "RUBY VERSION"
          ruby_version = line
        when "BUNDLED WITH"
          bundled_with = line
        end
      end

      Lockfile.new(
        git_sources: git_sources,
        path_sources: path_sources,
        gem_specs: gem_specs,
        gem_remotes: gem_remotes,
        dependencies: dependencies,
        platforms: platforms,
        bundled_with: bundled_with,
        ruby_version: ruby_version
      )
    end

    # "foo (1.2.3)" => ["foo", "1.2.3"]
    def parse_spec_line(line)
      m = line.match(/\A(\S+)\s+\(([^)]+)\)\z/)
      return [nil, nil] unless m

      [m[1], m[2]]
    end

    # "rails (~> 7.0)!" or "rake" or "foo (>= 1.0, < 2.0)"
    #
    # The trailing "!" is Bundler's own signal that this dependency resolves
    # from a pinned, non-default source (GIT, PATH, or a scoped `source do
    # ... end` custom GEM remote) -- see SOURCE_PIN_MISMATCH in rules.rb,
    # which cross-checks it against where the gem is actually sourced.
    def parse_dependency_line(line)
      pinned = line.end_with?("!")
      line = line.delete_suffix("!")
      m = line.match(/\A(\S+)(?:\s+\(([^)]+)\))?\z/)
      return [nil, nil, nil] unless m

      [m[1], m[2], pinned]
    end
  end
end
