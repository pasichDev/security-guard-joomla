# Security Guard for Joomla

[![CI](https://github.com/pasichDev/security-guard-joomla/actions/workflows/ci.yml/badge.svg)](https://github.com/pasichDev/security-guard-joomla/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Joomla 3.10](https://img.shields.io/badge/Joomla-3.10-5091cd.svg)](https://www.joomla.org/)

**English** · [Українська](README.uk.md)

A complete web application firewall (WAF) for **Joomla 3.10** — distributed as a single
installable package that bundles an admin component and a system plugin.

## Features

- 🛡️ **WAF** — request filtering and rule-based blocking
- 🍯 **Honeypot** — trap and identify malicious bots
- 📊 **Behavior scoring** — risk score per visitor
- 📈 **Live dashboard** + Grafana-style **traffic monitor**
- 🌊 **DDoS detection**
- 🌍 **Geo-tracking** of requests
- 🇬🇧 🇺🇦 English & Ukrainian translations

## Installation

1. Download `pkg_securityguard-<version>.zip` from the
   [latest release](https://github.com/pasichDev/security-guard-joomla/releases/latest).
2. In Joomla admin: **System → Install → Extensions → Upload Package File**.
3. Upload the package — the component and system plugin are installed together.
4. Enable the **System – Security Guard** plugin under **Extensions → Plugins**.

Once installed, Joomla checks this repository's update server and offers in-admin updates
for new releases automatically.

## Building from source

Plain PHP — no compilation. The build assembles the source in `src/` into a single
installable archive `pkg_securityguard-<version>.zip` in the repository root. That one
package installs both the component and the system plugin.

```bash
bash build/build.sh
```

The build uses the `zip` tool when available and falls back to Python, so it runs on Linux,
macOS and Windows alike. Releases are distributed only through
[GitHub Releases](https://github.com/pasichDev/security-guard-joomla/releases) — there is no
checked-in build output.

## Repository layout

```
src/                          source code
  com_securityguard/          admin component
  plg_system_securityguard/   system plugin
  pkg_securityguard.xml       package manifest (version source of truth)
build/build.sh                build script
updates/updates.xml.tmpl      Joomla update-server template
.github/workflows/            CI (build/lint) and release automation
docs/                         documentation (English)
```

## Releases & CI

- **CI** lints PHP (`php -l`), validates XML manifests, and builds the package on every push
  and pull request; **Commit Lint** validates commit messages on pull requests.
- **Releases are automated** with [semantic-release](https://semantic-release.gitbook.io/):
  pushing [Conventional Commits](https://www.conventionalcommits.org/) to `main` computes
  the next version, bumps the manifests, updates the changelog, publishes a GitHub Release
  with the package, and refreshes the Joomla update server on GitHub Pages. No manual tags.

## Contributing

Commits follow [Conventional Commits](docs/commit-convention.md) and drive automated
releases. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/](docs/). Issues and pull
requests are welcome.

## Support

If this project helps secure your site, you can support its development:

- ☕ Ko-fi — https://ko-fi.com/pasichdev
- 💝 Donatello — https://donatello.to/pasichDev

For questions, the best way to reach the author is by email:
**[apasichnik9@gmail.com](mailto:apasichnik9@gmail.com)** — or open an issue.

## License

[GNU GPL v2 or later](LICENSE) © pasichDev
