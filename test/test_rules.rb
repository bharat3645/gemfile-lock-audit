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

  def custom_remote
    @custom_remote ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "custom_remote.lock")))
  end

  def multi_source
    @multi_source ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "multi_source.lock")))
  end

  def pin_mismatch
    @pin_mismatch ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "pin_mismatch.lock")))
  end

  def dangling_dependency_fixture
    @dangling_dependency_fixture ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "dangling_dependency.lock")))
  end

  def orphaned_spec_fixture
    @orphaned_spec_fixture ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "orphaned_spec.lock")))
  end

  def git_path_adjacency
    @git_path_adjacency ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "git_path_adjacency.lock")))
  end

  def constraint_violation_fixture
    @constraint_violation_fixture ||= GemfileLockAudit::Parser.parse(File.read(File.join(FIXTURES, "constraint_violation.lock")))
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

  def test_custom_gem_remote_ignores_default_rubygems_source
    assert_empty GemfileLockAudit::Rules.custom_gem_remote(clean)
    assert_empty GemfileLockAudit::Rules.custom_gem_remote(risky)
  end

  def test_custom_gem_remote_flags_non_default_source
    findings = GemfileLockAudit::Rules.custom_gem_remote(custom_remote)
    assert_equal 1, findings.length
    assert_equal "CUSTOM_GEM_REMOTE", findings.first.rule_id
    assert_equal :medium, findings.first.severity
    assert_equal "https://gems.internal.example.com/", findings.first.subject
  end

  def test_custom_gem_remote_deduplicates_repeated_remotes
    lockfile = GemfileLockAudit::Parser.parse(
      "GEM\n  remote: https://mirror.example.com/\n  specs:\n    a (1.0)\n" \
      "GEM\n  remote: https://mirror.example.com/\n  specs:\n    b (1.0)\n" \
      "PLATFORMS\n  ruby\nDEPENDENCIES\n  a\n  b\n"
    )
    findings = GemfileLockAudit::Rules.custom_gem_remote(lockfile)
    assert_equal 1, findings.length
  end

  def test_custom_source_dependency_ignores_default_remote_gems
    assert_empty GemfileLockAudit::Rules.custom_source_dependency(clean)
    assert_empty GemfileLockAudit::Rules.custom_source_dependency(risky)
  end

  def test_custom_source_dependency_flags_only_the_gem_from_the_scoped_source
    findings = GemfileLockAudit::Rules.custom_source_dependency(multi_source)
    assert_equal 1, findings.length
    assert_equal "CUSTOM_SOURCE_DEPENDENCY", findings.first.rule_id
    assert_equal :info, findings.first.severity
    assert_equal "innerbuild", findings.first.subject
  end

  def test_custom_source_dependency_does_not_flag_git_or_path_specs
    # git_source_present/path_source_present already cover GIT and PATH; this
    # rule should stay scoped to :rubygems specs only, since a spec's
    # `remote` field is nil (not "custom") for git/path sources.
    findings = GemfileLockAudit::Rules.custom_source_dependency(risky)
    rule_subjects = findings.map(&:subject)
    refute_includes rule_subjects, "patched-gem"
    refute_includes rule_subjects, "local-tool"
  end

  def test_source_pin_mismatch_flags_missing_bang_for_custom_source_gem
    findings = GemfileLockAudit::Rules.source_pin_mismatch(pin_mismatch)
    finding = findings.find { |f| f.subject == "innerbuild" }
    refute_nil finding
    assert_equal "SOURCE_PIN_MISMATCH", finding.rule_id
    assert_equal :medium, finding.severity
  end

  def test_source_pin_mismatch_flags_stray_bang_for_default_source_gem
    findings = GemfileLockAudit::Rules.source_pin_mismatch(pin_mismatch)
    finding = findings.find { |f| f.subject == "rake" }
    refute_nil finding
    assert_equal "SOURCE_PIN_MISMATCH", finding.rule_id
  end

  def test_source_pin_mismatch_silent_on_internally_consistent_lockfiles
    # clean/risky/multi_source have no GIT/PATH/custom-remote gems that
    # disagree with their DEPENDENCIES "!" marker. custom_remote's one
    # scoped-source gem is correctly pinned with "!", so it's silent too.
    assert_empty GemfileLockAudit::Rules.source_pin_mismatch(clean)
    assert_empty GemfileLockAudit::Rules.source_pin_mismatch(risky)
    assert_empty GemfileLockAudit::Rules.source_pin_mismatch(multi_source)
    assert_empty GemfileLockAudit::Rules.source_pin_mismatch(custom_remote)
  end

  def test_dangling_dependency_flags_gem_with_no_matching_spec
    findings = GemfileLockAudit::Rules.dangling_dependency(dangling_dependency_fixture)
    assert_equal 1, findings.length
    assert_equal "DANGLING_DEPENDENCY", findings.first.rule_id
    assert_equal :high, findings.first.severity
    assert_equal "ghost-gem", findings.first.subject
  end

  def test_dangling_dependency_does_not_flag_resolvable_gem
    findings = GemfileLockAudit::Rules.dangling_dependency(dangling_dependency_fixture)
    refute_includes findings.map(&:subject), "rake"
  end

  def test_dangling_dependency_silent_on_internally_consistent_lockfiles
    # Every DEPENDENCIES entry in these fixtures has a matching spec in
    # GIT, PATH, or GEM -- none of them are missing a spec outright.
    assert_empty GemfileLockAudit::Rules.dangling_dependency(clean)
    assert_empty GemfileLockAudit::Rules.dangling_dependency(risky)
    assert_empty GemfileLockAudit::Rules.dangling_dependency(multi_source)
    assert_empty GemfileLockAudit::Rules.dangling_dependency(custom_remote)
    assert_empty GemfileLockAudit::Rules.dangling_dependency(pin_mismatch)
  end

  def test_constraint_violation_flags_gem_whose_resolved_version_fails_the_constraint
    findings = GemfileLockAudit::Rules.constraint_violation(constraint_violation_fixture)
    assert_equal 1, findings.length
    finding = findings.first
    assert_equal "CONSTRAINT_VIOLATION", finding.rule_id
    assert_equal :high, finding.severity
    assert_equal "rake", finding.subject
    assert_match(/~> 13\.0/, finding.message)
    assert_match(/12\.3\.3/, finding.message)
  end

  def test_constraint_violation_does_not_flag_unconstrained_dependency
    findings = GemfileLockAudit::Rules.constraint_violation(constraint_violation_fixture)
    refute_includes findings.map(&:subject), "thor"
  end

  def test_constraint_violation_silent_on_internally_consistent_lockfiles
    # Every constrained DEPENDENCIES entry in these fixtures resolves to a
    # version that actually satisfies its own constraint.
    assert_empty GemfileLockAudit::Rules.constraint_violation(clean)
    assert_empty GemfileLockAudit::Rules.constraint_violation(risky)
    assert_empty GemfileLockAudit::Rules.constraint_violation(multi_source)
    assert_empty GemfileLockAudit::Rules.constraint_violation(custom_remote)
    assert_empty GemfileLockAudit::Rules.constraint_violation(pin_mismatch)
    assert_empty GemfileLockAudit::Rules.constraint_violation(dangling_dependency_fixture)
    assert_empty GemfileLockAudit::Rules.constraint_violation(orphaned_spec_fixture)
  end

  def test_constraint_violation_checks_git_and_path_sourced_gems_too
    lockfile = GemfileLockAudit::Parser.parse(
      "GIT\n  remote: https://github.com/example/patched-gem.git\n  revision: abc123\n  tag: v1\n  specs:\n" \
      "    patched-gem (0.3.0)\n" \
      "PLATFORMS\n  ruby\nDEPENDENCIES\n  patched-gem (~> 1.0)!\n"
    )
    findings = GemfileLockAudit::Rules.constraint_violation(lockfile)
    assert_equal 1, findings.length
    assert_equal "patched-gem", findings.first.subject
  end

  def test_constraint_violation_ignores_unparseable_constraint_instead_of_raising
    lockfile = GemfileLockAudit::Parser.parse(
      "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n" \
      "PLATFORMS\n  ruby\nDEPENDENCIES\n  rake (not a real constraint)\n"
    )
    assert_empty GemfileLockAudit::Rules.constraint_violation(lockfile)
  end

  def test_orphaned_spec_flags_gem_unreachable_from_dependencies
    findings = GemfileLockAudit::Rules.orphaned_spec(orphaned_spec_fixture)
    assert_equal 1, findings.length
    assert_equal "ORPHANED_SPEC", findings.first.rule_id
    assert_equal :low, findings.first.severity
    assert_equal "orphan-gem", findings.first.subject
  end

  def test_orphaned_spec_does_not_flag_gem_reachable_only_transitively
    # rspec-core isn't in DEPENDENCIES directly -- it's only reachable by
    # walking rspec's own nested requirement list. It must not be flagged.
    findings = GemfileLockAudit::Rules.orphaned_spec(orphaned_spec_fixture)
    refute_includes findings.map(&:subject), "rspec-core"
    refute_includes findings.map(&:subject), "rspec"
    refute_includes findings.map(&:subject), "rake"
  end

  def test_orphaned_spec_silent_on_internally_consistent_lockfiles
    # Every gem_specs entry in these fixtures is either listed directly in
    # DEPENDENCIES or reachable transitively -- none has a dead, unreachable
    # spec.
    assert_empty GemfileLockAudit::Rules.orphaned_spec(clean)
    assert_empty GemfileLockAudit::Rules.orphaned_spec(risky)
    assert_empty GemfileLockAudit::Rules.orphaned_spec(multi_source)
    assert_empty GemfileLockAudit::Rules.orphaned_spec(custom_remote)
    assert_empty GemfileLockAudit::Rules.orphaned_spec(pin_mismatch)
    assert_empty GemfileLockAudit::Rules.orphaned_spec(dangling_dependency_fixture)
  end

  def test_orphaned_spec_traces_reachability_through_git_and_path_gems
    # widget-core and thor are required only by the git gem "widget", and
    # toolkit-support only by the path gem "toolkit" -- none appears in
    # DEPENDENCIES directly or in another GEM spec's requirements. Before
    # git/path adjacency was captured these three GEM specs were falsely
    # flagged as orphaned; reachability now seeds from the git/path
    # DEPENDENCIES roots and walks their nested requirements into GEM.
    assert_empty GemfileLockAudit::Rules.orphaned_spec(git_path_adjacency)
  end

  def test_orphaned_spec_still_flags_true_orphan_alongside_git_path_adjacency
    # The git gem "app" pulls in "used-gem", but "dead-gem" is required by
    # nothing at all. Traversing git/path adjacency must not blanket-whitelist
    # every GEM spec -- a genuinely unreachable one is still caught.
    lockfile = GemfileLockAudit::Parser.parse(
      "GIT\n  remote: https://github.com/example/app.git\n  revision: abc123\n  tag: v1\n  specs:\n" \
      "    app (1.0)\n      used-gem\n" \
      "GEM\n  remote: https://rubygems.org/\n  specs:\n    used-gem (1.0)\n    dead-gem (1.0)\n" \
      "PLATFORMS\n  ruby\nDEPENDENCIES\n  app!\n"
    )
    subjects = GemfileLockAudit::Rules.orphaned_spec(lockfile).map(&:subject)
    assert_includes subjects, "dead-gem"
    refute_includes subjects, "used-gem"
  end
end
