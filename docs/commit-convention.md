# Commit Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.
Every commit is validated automatically — by a local git hook on your machine (husky +
commitlint) and by the **Commit Lint** GitHub Actions job on every pull request.

Releases are fully automated: [semantic-release](https://semantic-release.gitbook.io/)
reads the commit history on `main`, decides the next version, bumps all Joomla manifests,
updates the changelog, builds the package and publishes the GitHub Release.

## Format

```
<type>(<scope>): <subject>

[body]

[footer]
```

---

## Type

Required. Determines whether a release is triggered and which version component is bumped.

| Type | When to use | Version impact |
|---|---|---|
| `feat` | New functionality | minor — `1.3.0 → 1.4.0` |
| `fix` | Bug fix | patch — `1.3.0 → 1.3.1` |
| `perf` | Performance improvement | patch |
| `refactor` | Internal restructuring, no behaviour change | patch |
| `chore` | Maintenance, config changes | no release |
| `ci` | CI/CD pipeline changes | no release |
| `docs` | Documentation only | no release |
| `test` | Adding or fixing tests | no release |
| `style` | Formatting, whitespace | no release |
| `build` | Build script / packaging changes | no release |

---

## Scope

Required for this repository. Tells reviewers and the changelog which part of the
extension is affected.

| Scope | Covers |
|---|---|
| `component` | `com_securityguard` — admin UI, controller, models, views |
| `plugin` | `plg_system_securityguard` — the system plugin |
| `waf` | Request filtering / blocking rules |
| `honeypot` | Honeypot traps |
| `scoring` | Behavior scoring |
| `dashboard` | Live dashboard |
| `traffic` | Traffic monitor |
| `ddos` | DDoS detection |
| `geo` | Geo-tracking |
| `sql` | Install / update schema |
| `i18n` | Language files |
| `build` | Build script, packaging |
| `ci` | GitHub Actions workflows |
| `deps` | Dependency upgrades |
| `release` | Automated commits made by semantic-release |
| `repo` | Repository meta: README, funding, license, contributing |

---

## Subject

Required. A short imperative description of the change.

- minimum 10 characters
- maximum 100 characters (whole header line)
- starts with a lowercase letter
- no period at the end
- answers *"what does this commit do?"*, not *"what was I doing?"*

```
# ✓ correct
feat(waf): add rate-limit rule for repeated 404 probes
fix(component): enforce core.manage on destructive tasks
perf(dashboard): cache hourly attack aggregation for live stats

# ✗ incorrect
fix: fix bug                   ← missing scope, too short
feat(waf): Added a rule.       ← uppercase start, trailing period
WIP                            ← not conventional commits at all
```

---

## Breaking Changes

A change that breaks backwards compatibility triggers a **major bump** (`1.x.y → 2.0.0`).

**1. Exclamation mark `!` after type/scope:**

```
feat(sql)!: drop the legacy v1 blocks table
```

**2. `BREAKING CHANGE:` footer:**

```
feat(plugin): new scoring storage format

BREAKING CHANGE: scores from < 2.0 are not migrated and will be reset on upgrade.
```

Both forms produce identical results — use whichever fits the commit better.

---

## How Automatic Releases Work

On every push to `main`, semantic-release scans all commits since the last tag and picks
the **highest-impact type**:

```
fix + fix + fix        →  patch    1.3.0 → 1.3.1
fix + fix + feat       →  minor    1.3.0 → 1.4.0
fix + feat + BREAKING  →  major    1.3.0 → 2.0.0
chore + ci + docs      →  no release
```

Once the version is determined, the pipeline automatically:

1. Bumps `<version>` in all three manifests
   (`pkg_securityguard.xml`, `com_securityguard/securityguard.xml`,
   `plg_system_securityguard/securityguard.xml`).
2. Generates / updates `CHANGELOG.md`.
3. Builds `pkg_securityguard-<version>.zip`.
4. Commits the bumped manifests and changelog back — `chore(release): <version> [skip ci]`.
5. Creates git tag `v<version>` and a GitHub Release with the package attached.
6. Renders `updates.xml` and publishes it to GitHub Pages for in-admin auto-updates.

You never edit the version by hand — just land conventional commits on `main`.

---

## Local Validation

After `npm install`, the `commit-msg` git hook runs commitlint on every commit:

```bash
git commit -m "wip"

⧗   input: wip
✖   subject may not be empty [subject-empty]
✖   type may not be empty [type-empty]

✖   found 2 problems, 0 warnings
husky - commit-msg hook exited with code 1
```

The commit is **not created**. Fix the message and try again.

> Bypassing the hook (`--no-verify`) doesn't help — the **Commit Lint** CI job validates
> the same rules on the pull request and blocks the merge.
