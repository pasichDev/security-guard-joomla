# Development

## Repository layout

```
src/
  com_securityguard/          admin component
    admin/                    controllers, models, views, SQL, language
    media/                    CSS / JS
    site/                     site-side files
    securityguard.xml         component manifest
  plg_system_securityguard/   system plugin
    securityguard.php         plugin logic
    securityguard.xml         plugin manifest
    language/                 plugin language files
  language/                   package-level language placeholders
  pkg_securityguard.xml       package manifest (version source of truth)
build/build.sh                build script
updates/updates.xml.tmpl      Joomla update-server template
.github/workflows/            CI and release workflows
```

This is plain PHP for Joomla 3.10 — there is no compilation step. "Building" means packing
the source into installable `.zip` archives.

## Building

```bash
bash build/build.sh
```

Produces a single archive in the repository root:

| Artifact | Contents |
| --- | --- |
| `pkg_securityguard-<version>.zip` | Full package — installs the component and the system plugin together |

The script reads the version from `src/pkg_securityguard.xml`. It uses the `zip` tool when
available and otherwise falls back to Python's `zipfile`, so it runs on Linux, macOS and
Windows. The archive is git-ignored and distributed only through GitHub Releases.

## Local checks

The same checks CI runs:

```bash
# PHP syntax
find src -name '*.php' -print0 | xargs -0 -n1 php -l

# XML manifests
find src -name '*.xml' -print0 | xargs -0 -n1 xmllint --noout
```

## Package layout

The installable package zip contains:

```
pkg_securityguard.xml          package manifest
packages/
  com_securityguard.zip        component
  plg_system_securityguard.zip system plugin
language/                      package-level language placeholders
```

The `packages/` folder matches `<files folder="packages">` in the package manifest, which
tells Joomla to install both bundled extensions.

## Manual installation for testing

Install `pkg_securityguard-<version>.zip` via **System → Install → Extensions → Upload
Package File**, then enable **System – Security Guard** under **Extensions → Plugins**.
