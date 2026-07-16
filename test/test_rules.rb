# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/gemfile_lock_audit"

class TestRules < Minitest::Test
  FIXTURES = File.join(__dir__, "fixtures")

  def clean
    @clean ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "clean.lock")))
  end

  def risky
    @risky ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "risky.lock")))
  end

  def test_clean_lockfile_has_no_git_or_path_findings
    assert_empty GemfileLockAudit::Rules.git_source_present(clean)
    assert_empty GemfileLockAudit::Rules.path_source_present(clean)
    assert_empty GemfileLockAudit::Rules.git_branch_source(clean)
  end

  def test_clean_lockfile_has_no_missing_bundled_with
    assert_empty GemfileLockAudit::Rules.missing_bundled_with(clean)
  end

  def test_git_branch_source_flags_floating_branch
    findings = GemfileLockAudit::Rules.git_branch_source(risky)
    assert_equal 1, findings.length
    assert_equal "GIT_TRACKS_BRANCH", findings.first.rule_id
    assert_equal :high, findings.first.severity
  end

  def test_git_source_present_flags_any_git_dependency
    findings = GemfileLockAudit::Rules.git_source_present(risky)
    assert_equal 1, findings.length
    assert_equal :medium, findings.first.severity
  end

  def test_path_source_present_flags_local_path
    findings = GemfileLockAudit::Rules.path_source_present(risky)
    assert_equal 1, findings.length
    assert_equal :info, findings.first.severity
    assert_equal "../local-tool", findings.first.subject
  end

  def test_prerelease_pin_detects_rc_version
    findings = GemfileLockAudit::Rules.prerelease_pin(risky)
    subjects = findings.map(&:subject)
    assert_includes subjects, "rake"
  end

  def test_prerelease_pin_ignores_clean_versions
    assert_empty GemfileLockAudit::Rules.prerelease_pin(clean)
  end

  def test_missing_bundled_with_flagged_when_absent
    findings = GemfileLockAudit::Rules.missing_bundled_with(risky)
    assert_equal 1, findings.length
    assert_equal "MISSING_BUNDLED_WITH", findings.first.rule_id
  end

  def test_possible_typosquat_flags_near_miss_name
    findings = GemfileLockAudit::Rules.possible_typosquat(risky)
    subjects = findings.map(&:subject)
    assert_includes subjects, "railes"
  end

  def test_possible_typosquat_does_not_flag_known_gems
    findings = GemfileLockAudit::Rules.possible_typosquat(clean)
    assert_empty findings
  end

  def test_levenshtein_basic_cases
    assert_equal 0, GemfileLockAudit::Rules.levenshtein("rails", "rails")
    assert_equal 1, GemfileLockAudit::Rules.levenshtein("rails", "railes")
    assert_equal 3, GemfileLockAudit::Rules.levenshtein("kitten", "sitting")
  end

  def test_close_but_not_equal_rejects_identical_strings
    refute GemfileLockAudit::Rules.close_but_not_equal?("rails", "rails")
  end

  def test_unconstrained_dependency_flags_bare_gem_names
    findings = GemfileLockAudit::Rules.unconstrained_dependency(risky)
    names = findings.map(&:subject)
    assert_includes names, "railes"
  end

  def test_unconstrained_dependency_ignores_pinned_gems
    findings = GemfileLockAudit::Rules.unconstrained_dependency(clean)
    assert_empty findings
  end
end
