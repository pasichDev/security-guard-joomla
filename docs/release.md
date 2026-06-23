# Release process

## Versioning

The version lives in three manifests and they must stay in sync:

- `src/pkg_securityguard.xml`
- `src/com_securityguard/securityguard.xml`
- `src/plg_system_securityguard/securityguard.xml`

`src/pkg_securityguard.xml` is the source of truth the build and release workflow read.
The project follows [Semantic Versioning](https://semver.org/).

## Steps

1. Bump `<version>` in all three manifests.
2. Add a section to `CHANGELOG.md`.
3. If the schema changed, add an update SQL file under
   `src/com_securityguard/admin/sql/updates/mysql/<version>.sql`.
4. Commit the changes.
5. Create and push the tag:

   ```bash
   git tag v<version>
   git push origin v<version>
   ```

## What the release workflow does

Triggered by pushing a `v*` tag (`.github/workflows/release.yml`):

1. Verifies the tag matches `<version>` in `src/pkg_securityguard.xml` (fails on mismatch).
2. Lints PHP and validates XML manifests.
3. Runs `build/build.sh`.
4. Creates a GitHub Release with the three zip artifacts and auto-generated notes.
5. Renders `updates/updates.xml.tmpl` with the new version and the release download URL,
   then publishes it to GitHub Pages (`gh-pages` branch).

## Update server

The package manifest points Joomla at:

```
https://pasichdev.github.io/security-guard-joomla/updates.xml
```

After a release, installed sites see the new version under **Components → Joomla Update /
Update** and can upgrade in-admin. GitHub Pages must be enabled for the `gh-pages` branch
(the first release workflow run creates that branch).
