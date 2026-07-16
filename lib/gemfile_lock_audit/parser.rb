# frozen_string_literal: true

module GemfileLockAudit
  # Raised when a file doesn't look like a Gemfile.lock at all.
  class ParseError < StandardError; end

  GemSpec = Struct.new(:name, :version, :source, keyword_init: true)
  GitSource = Struct.new(:remote, :revision, :branch, :tag, :ref, :gems, keyword_init: true)
  PathSource = Struct.new(:remote, :gems, keyword_init: true)

  Lockfile = Struct.new(
    :git_sources,      # Array[GitSource]
    :path_sources,     # Array[PathSource]
    :gem_specs,        # Hash[String, GemSpec] -- name => spec, from the GEM section
    :dependencies,      # Array[{name:, constraint:}] -- from the DEPENDENCIES section (top-level only)
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
      dependencies = []
      platforms = []
      bundled_with = nil
      ruby_version = nil

      section = nil
      subsection = nil # within GIT/PATH/GEM: :remote_block, :specs
      current_source = nil # the GitSource/PathSource currently being built

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
            subsection = :specs if key.strip == "specs"
          elsif indent == 4 && subsection == :specs
            name, version = parse_spec_line(line)
            gem_specs[name] = GemSpec.new(name: name, version: version, source: :rubygems) if name
          end
          # deeper indents (>4) are transitive sub-dependency listings; not needed for auditing
        when "PLATFORMS"
          platforms << line
        when "DEPENDENCIES"
          name, constraint = parse_dependency_line(line)
          dependencies << { name: name, constraint: constraint } if name
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
    def parse_dependency_line(line)
      line = line.delete_suffix("!") # bang marks gems pinned by a GIT/PATH source
      m = line.match(/\A(\S+)(?:\s+\(([^)]+)\))?\z/)
      return [nil, nil] unless m

      [m[1], m[2]]
    end
  end
end
