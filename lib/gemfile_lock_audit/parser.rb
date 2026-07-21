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
    :spec_dependencies, # Hash[String, Array[String]] -- spec name (from a GEM, GIT, or PATH
                         # block) => the names of the gems *that spec itself* declares as its
                         # own runtime dependencies (Bundler nests these one indent level
                         # deeper than the spec line, e.g. "rspec-core" under "rspec (3.12.0)",
                         # and likewise under a git/path gem's own spec line). This is
                         # an adjacency list, not another set of specs to audit -- version
                         # constraints on these nested lines are discarded since only the
                         # name is needed to trace reachability from DEPENDENCIES down
                         # through the dependency graph (see Rules.orphaned_spec).
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
      spec_dependencies = {}
      platforms = []
      bundled_with = nil
      ruby_version = nil

      section = nil
      subsection = nil # within GIT/PATH/GEM: :remote_block, :specs
      current_source = nil # the GitSource/PathSource currently being built
      current_gem_remote = nil # the "remote:" value of the GEM block currently being read
      current_gem_spec_name = nil # the GEM spec whose nested dependency lines we're reading
      current_source_spec_name = nil # the GIT/PATH spec whose nested dependency lines we're reading

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
            current_source_spec_name = nil
          when "PATH"
            current_source = PathSource.new(gems: [])
            path_sources << current_source
            current_source_spec_name = nil
          when "GEM"
            # A lockfile can have more than one top-level GEM block (e.g. one
            # per scoped `source "..." do ... end` in the Gemfile) -- reset so
            # specs in this block aren't attributed to the previous block's
            # remote.
            current_gem_remote = nil
            current_gem_spec_name = nil
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
          elsif subsection == :specs
            if indent == 4
              # The gem this GIT/PATH source actually provides, e.g.
              # "patched-gem (0.3.0)".
              name, version = parse_spec_line(line)
              if name
                current_source.gems << GemSpec.new(name: name, version: version, source: section == "GIT" ? :git : :path)
                current_source_spec_name = name
              end
            elsif indent > 4 && current_source_spec_name
              # A dependency the current GIT/PATH spec itself declares, nested
              # one indent level deeper -- structurally identical to the GEM
              # section's nested requirement lines. Only the name feeds the
              # shared spec_dependencies adjacency list (the constraint is
              # discarded) so ORPHANED_SPEC reachability can trace from a
              # git/path gem down into the GEM specs it pulls in. These nested
              # lines are requirements, not gems this source provides, so they
              # must NOT be added to current_source.gems.
              dep_name = parse_nested_dependency_name(line)
              (spec_dependencies[current_source_spec_name] ||= []) << dep_name if dep_name
            end
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
            if name
              gem_specs[name] = GemSpec.new(name: name, version: version, source: :rubygems, remote: current_gem_remote)
              current_gem_spec_name = name
            end
          elsif indent > 4 && subsection == :specs && current_gem_spec_name
            # A dependency the current spec itself declares, e.g.
            # "rspec-core (~> 3.12.0)" nested under "rspec (3.12.0)". Only the
            # name feeds the adjacency list -- the version constraint here is
            # what *that* gem's own Gemfile-equivalent would require, not
            # what's actually resolved (that's gem_specs[name].version).
            dep_name = parse_nested_dependency_name(line)
            if dep_name
              (spec_dependencies[current_gem_spec_name] ||= []) << dep_name
            end
          end
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
        spec_dependencies: spec_dependencies,
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

    # "rspec-core (~> 3.12.0)" or "rake" => "rspec-core" / "rake"
    #
    # These are the nested lines under a GEM spec, listing the dependencies
    # that spec itself requires. Unlike parse_spec_line, the version part is
    # optional here (a bare dependency name with no constraint is legal),
    # and unlike parse_dependency_line there's no trailing "!" to strip --
    # only DEPENDENCIES entries get that marker.
    def parse_nested_dependency_name(line)
      m = line.match(/\A(\S+)/)
      m && m[1]
    end
  end
end
