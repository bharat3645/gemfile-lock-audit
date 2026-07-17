# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/gemfile_lock_audit"

class TestParser < Minitest::Test
  FIXTURES = File.join(__dir__, "fixtures")

  def test_parses_clean_lockfile
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "clean.lock")))

    assert_equal %w[minitest rake rspec rspec-core], lf.gem_specs.keys
    assert_equal "5.18.0", lf.gem_specs["minitest"].version
    assert_equal :rubygems, lf.gem_specs["minitest"].source
    assert_equal ["ruby"], lf.platforms
    assert_equal "2.4.10", lf.bundled_with
    assert_equal 3, lf.dependencies.length
    assert lf.git_sources.empty?
    assert lf.path_sources.empty?
  end

  def test_parses_git_and_path_sources
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "risky.lock")))

    assert_equal 1, lf.git_sources.length
    git = lf.git_sources.first
    assert_equal "https://github.com/example/patched-gem.git", git.remote
    assert_equal "main", git.branch
    assert_nil git.tag
    assert_equal ["patched-gem"], git.gems.map(&:name)

    assert_equal 1, lf.path_sources.length
    path = lf.path_sources.first
    assert_equal "../local-tool", path.remote
    assert_equal ["local-tool"], path.gems.map(&:name)

    assert_nil lf.bundled_with
  end

  def test_dependency_constraints_parsed
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "clean.lock")))
    dep = lf.dependencies.find { |d| d[:name] == "rake" }
    assert_equal "~> 13.0", dep[:constraint]
  end

  def test_bang_suffix_stripped_from_dependency_name
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "risky.lock")))
    dep = lf.dependencies.find { |d| d[:name] == "patched-gem" }
    refute_nil dep
    assert_nil dep[:constraint]
  end

  def test_rejects_unrecognized_input
    assert_raises(GemfileLockAudit::ParseError) do
      GemfileLockAudit::Parser.parse("this is not a lockfile at all\njust some text\n")
    end
  end

  def test_empty_lines_are_skipped_safely
    lf = GemfileLockAudit::Parser.parse("GEM\n  remote: https://rubygems.org/\n\n  specs:\n\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n")
    assert_equal ["rake"], lf.gem_specs.keys
  end

  def test_gem_remotes_captured_for_default_source
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "clean.lock")))
    assert_equal ["https://rubygems.org/"], lf.gem_remotes
  end

  def test_gem_remotes_captured_for_custom_source
    lf = GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "custom_remote.lock")))
    assert_equal ["https://gems.internal.example.com/"], lf.gem_remotes
    assert_equal ["innerbuild"], lf.gem_specs.keys
  end
end
