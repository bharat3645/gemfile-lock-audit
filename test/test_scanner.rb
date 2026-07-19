# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/gemfile_lock_audit"

class TestScanner < Minitest::Test
  FIXTURES = File.join(__dir__, "fixtures")

  def test_clean_lockfile_scores_high
    report = GemfileLockAudit::Scanner.scan_file(File.join(FIXTURES, "clean.lock"))
    assert_equal 100, report.score
    assert_equal "A", report.grade
  end

  def test_risky_lockfile_scores_low_with_expected_findings
    report = GemfileLockAudit::Scanner.scan_file(File.join(FIXTURES, "risky.lock"))
    rule_ids = report.findings.map(&:rule_id)

    assert_includes rule_ids, "GIT_TRACKS_BRANCH"
    assert_includes rule_ids, "GIT_SOURCE"
    assert_includes rule_ids, "PATH_SOURCE"
    assert_includes rule_ids, "PRERELEASE_PIN"
    assert_includes rule_ids, "POSSIBLE_TYPOSQUAT"
    assert_includes rule_ids, "MISSING_BUNDLED_WITH"

    assert_operator report.score, :<, 75
    assert_includes %w[C D F], report.grade
  end

  def test_custom_remote_lockfile_flags_non_default_source
    report = GemfileLockAudit::Scanner.scan_file(File.join(FIXTURES, "custom_remote.lock"))
    rule_ids = report.findings.map(&:rule_id)

    assert_includes rule_ids, "CUSTOM_GEM_REMOTE"
    assert_equal 92, report.score
    assert_equal "A", report.grade
  end

  def test_multi_source_lockfile_flags_remote_and_the_specific_dependency
    report = GemfileLockAudit::Scanner.scan_file(File.join(FIXTURES, "multi_source.lock"))
    rule_ids = report.findings.map(&:rule_id)

    assert_includes rule_ids, "CUSTOM_GEM_REMOTE"
    assert_includes rule_ids, "CUSTOM_SOURCE_DEPENDENCY"

    dependency_finding = report.findings.find { |f| f.rule_id == "CUSTOM_SOURCE_DEPENDENCY" }
    assert_equal "innerbuild", dependency_finding.subject

    # CUSTOM_SOURCE_DEPENDENCY is :info (0-weight) -- it adds detail to the
    # already-scored CUSTOM_GEM_REMOTE (:medium, -8) finding, not a second
    # deduction, so a lockfile with one custom-sourced gem still lands at 92.
    assert_equal 92, report.score
    assert_equal "A", report.grade
  end

  def test_pin_mismatch_lockfile_flags_both_directions
    report = GemfileLockAudit::Scanner.scan_file(File.join(FIXTURES, "pin_mismatch.lock"))
    mismatch_findings = report.findings.select { |f| f.rule_id == "SOURCE_PIN_MISMATCH" }

    assert_equal 2, mismatch_findings.length
    assert_includes mismatch_findings.map(&:subject), "innerbuild"
    assert_includes mismatch_findings.map(&:subject), "rake"
  end

  def test_score_to_grade_boundaries
    assert_equal "A", GemfileLockAudit::Scanner.score_to_grade(100)
    assert_equal "A", GemfileLockAudit::Scanner.score_to_grade(90)
    assert_equal "B", GemfileLockAudit::Scanner.score_to_grade(89)
    assert_equal "B", GemfileLockAudit::Scanner.score_to_grade(75)
    assert_equal "C", GemfileLockAudit::Scanner.score_to_grade(74)
    assert_equal "C", GemfileLockAudit::Scanner.score_to_grade(60)
    assert_equal "D", GemfileLockAudit::Scanner.score_to_grade(59)
    assert_equal "D", GemfileLockAudit::Scanner.score_to_grade(40)
    assert_equal "F", GemfileLockAudit::Scanner.score_to_grade(39)
    assert_equal "F", GemfileLockAudit::Scanner.score_to_grade(0)
  end

  def test_scan_file_raises_parse_error_for_missing_file
    assert_raises(GemfileLockAudit::ParseError) do
      GemfileLockAudit::Scanner.scan_file("/nonexistent/Gemfile.lock")
    end
  end

  def test_scan_text_accepts_raw_string
    report = GemfileLockAudit::Scanner.scan_text(File.read(File.join(FIXTURES, "clean.lock")))
    assert_equal "A", report.grade
  end
end
