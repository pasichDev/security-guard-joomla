# Release process

Releases are **fully automated** with [semantic-release](https://semantic-release.gitbook.io/).
You do not bump versions or create tags by hand.

## How it works

Every push to `main` runs the **Release** workflow. semantic-release analyzes the commit
messages since the last release (see [commit-convention.md](commit-convention.md)) and, if
there is a releasable change (`feat`, `fix`, `perf`, `refactor` or a breaking change):

1. Computes the next version from the commit types.
2. Stamps that version into all three manifests via `build/bump-version.sh`:
   - `src/pkg_securityguard.xml`
   - `src/com_securityguard/securityguard.xml`
   - `src/plg_system_securityguard/securityguard.xml`
3. Builds `pkg_securityguard-<version>.zip` with `build/build.sh`.
4. Renders `public/updates.xml` with `build/render-updates.sh`.
5. Updates `CHANGELOG.md`.
6. Commits the bumped manifests and changelog back as `chore(release): <version> [skip ci]`.
7. Creates git tag `v<version>` and a GitHub Release with the package attached.
8. Publishes `updates.xml` to the `gh-pages` branch (Joomla update server).

If only non-releasing commits are present (`chore`, `docs`, `ci`, `test`, `style`, `build`),
no release is created.

## To cut a release

Just land conventional commits on `main`:

```
fix(component): enforce core.manage on destructive tasks   → patch
feat(waf): add rate-limit rule for repeated 404 probes     → minor
feat(sql)!: drop the legacy v1 blocks table                → major
```

## One-time setup

These must be done once on the GitHub repository:

1. **Version baseline.** semantic-release continues from the latest `v*` git tag. To keep
   the existing `1.3.x` line (instead of restarting at `1.0.0`), push the baseline tag once:

   ```bash
   git tag v1.3.12
   git push origin v1.3.12
   ```

2. **GitHub Pages.** Enable Pages for the `gh-pages` branch (created by the first release)
   so the update server URL resolves.

3. **Actions permissions.** Settings → Actions → General → Workflow permissions →
   "Read and write permissions" (lets semantic-release push the release commit and tag).

## Update server

The package manifest points Joomla at:

```
https://pasichdev.github.io/security-guard-joomla/updates.xml
```

After a release, installed sites see the new version under **Components → Joomla Update /
Update** and can upgrade in-admin.
