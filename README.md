# gemfile-lock-audit

Offline supply-chain risk scanner for Bundler's `Gemfile.lock`. Point it at a
lockfile and it grades your dependency graph A-F based on concrete,
explainable risk signals — the same way [`mcp-sentinel`](https://github.com/bharat3645/mcp-sentinel)
and [`agent-tool-audit`](https://github.com/bharat3645/agent-tool-audit) grade
their respective inputs.

**Zero runtime dependencies. Zero network calls.** It parses the lockfile
text itself — no `bundle install`, no hitting rubygems.org, no executing
anything from the Gemfile. Just static analysis of what's already been
resolved and committed to your repo.

## Why

`Gemfile.lock` is supposed to be the one artifact that pins your dependency
graph exactly. But "pinned" isn't the same as "safe": a gem sourced from a
git branch instead of a tag will silently follow that branch on the next
`bundle update`; a local `path:` dependency won't resolve the same way on a
teammate's machine or in CI; a gem name one character off from `rails` is
easy to miss in a 40-line dependency block. None of this shows up unless you
go looking for it. `gemfile-lock-audit` goes looking for it.

## Install

```bash
git clone https://github.com/bharat3645/gemfile-lock-audit.git
cd gemfile-lock-audit
```

No `gem install` required to try it — it's plain Ruby stdlib:

```bash
ruby bin/gemfile-lock-audit path/to/Gemfile.lock
```

Requires Ruby 2.7+. If you'd rather install it as a gem, `gemfile-lock-audit.gemspec`
is set up for that (`gem build gemfile-lock-audit.gemspec && gem install ./gemfile-lock-audit-0.1.0.gem`).

## Usage

```bash
# Scan a specific lockfile
gemfile-lock-audit Gemfile.lock

# Scan multiple lockfiles (e.g. a monorepo with several apps)
gemfile-lock-audit app/Gemfile.lock api/Gemfile.lock

# Fail (non-zero exit) if any lockfile scores below 70 -- handy in CI
gemfile-lock-audit Gemfile.lock --fail-under 70
```

Example output:

```
Gemfile.lock
============

  [    HIGH] GIT_TRACKS_BRANCH: Git source "https://github.com/example/patched-gem.git" tracks branch 'main' instead of a fixed tag or ref. The lockfile pins a specific revision today, but the next `bundle update` will follow whatever that branch has become -- including commits nobody on this project has reviewed.
  [  MEDIUM] GIT_SOURCE: Gem(s) patched-gem are sourced directly from git (https://github.com/example/patched-gem.git) rather than a package registry. There's no publish/yank/signing step in between -- whatever is at that revision is what ships.
  [    INFO] PATH_SOURCE: Gem(s) local-tool are loaded from a local path (../local-tool). Harmless for local development, but this lockfile won't resolve as-is on another machine or in CI unless that path also exists there.
  [     LOW] PRERELEASE_PIN: 'rake' is locked to 13.0.0.rc1, which looks like a pre-release build (alpha/beta/rc/pre). Worth confirming that's intentional and not a leftover from local testing.
  [    INFO] MISSING_BUNDLED_WITH: No 'BUNDLED WITH' section -- the Bundler version used to resolve this lockfile isn't pinned, so different machines/CI runners could resolve dependencies slightly differently over time.
  [    HIGH] POSSIBLE_TYPOSQUAT: 'railes' is suspiciously similar to the well-known gem 'rails' but not identical -- worth a manual check that this isn't a typosquat before trusting it.

Score: 59/100 (grade D)
```

## What it checks

| Rule | Severity | What it catches |
|---|---|---|
| `GIT_TRACKS_BRANCH` | high | A git-sourced gem tracks a branch (not a tag/ref), so the next `bundle update` follows unreviewed commits |
| `POSSIBLE_TYPOSQUAT` | high | A gem name is a near-miss (Levenshtein distance ≤2) to a well-known gem |
| `DANGLING_DEPENDENCY` | high | A `DEPENDENCIES` entry has no matching spec anywhere in `GIT`/`PATH`/`GEM` -- the lockfile cannot actually resolve that gem; a clean `bundle lock` never produces this |
| `GIT_SOURCE` | medium | Any gem sourced directly from git instead of a registry |
| `CUSTOM_GEM_REMOTE` | medium | The `GEM` section resolves from something other than `https://rubygems.org/` (private server, internal mirror) |
| `SOURCE_PIN_MISMATCH` | medium | The `!` pin marker in `DEPENDENCIES` disagrees with where a gem is actually sourced in `GIT`/`PATH`/`GEM` -- a sign of a hand edit or a bad merge, since `bundle lock` itself never produces this |
| `CUSTOM_SOURCE_DEPENDENCY` | info | Per-gem detail for `CUSTOM_GEM_REMOTE`: names exactly which dependency resolves from that non-default remote, e.g. one pinned there by a scoped `source "..." do ... end` block in the Gemfile |
| `PRERELEASE_PIN` | low | A resolved version looks like an alpha/beta/rc/pre build |
| `PATH_SOURCE` | info | A gem is loaded from a local filesystem path |
| `UNCONSTRAINED_DEPENDENCY` | info | A top-level Gemfile dependency has no version constraint at all |
| `MISSING_BUNDLED_WITH` | info | The lockfile doesn't pin a Bundler version |

Grading: starts at 100, loses points per finding (high −15, medium −8, low
−3, info −0), floored at 0. 90+ is an A, 75+ a B, 60+ a C, 40+ a D, below
that an F.

## What it deliberately does *not* do

- No network calls — it won't check rubygems.org for yanked versions or
  known CVEs against resolved versions. That's a reasonable follow-up but
  changes the trust model of the tool itself (see `mcp-sentinel`'s README
  for the same reasoning), so it's out of scope for v0.1.
- No `bundle install` / no code execution from the scanned project.
- Not a full Bundler reimplementation — it parses the sections Bundler
  actually writes to `Gemfile.lock`, not arbitrary hand-edited lockfiles.

## Development

```bash
ruby test/test_parser.rb
ruby test/test_rules.rb
ruby test/test_scanner.rb
```

48 tests, `minitest` only (bundled with Ruby — no `gem install` needed to
run the test suite).

## Contributing

Issues and PRs welcome, especially new heuristic rules — see
`lib/gemfile_lock_audit/rules.rb` for the pattern (a rule is a module
function that takes a parsed `Lockfile` and returns an array of `Finding`s).

## License

MIT — see [LICENSE](./LICENSE).
