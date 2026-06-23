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

Plain PHP — no compilation. The build assembles the source in `src/` into installable zips.

```bash
bash build/build.sh
```

Output in `dist/`:

| Artifact | Contents |
| --- | --- |
| `pkg_securityguard-<version>.zip` | Full package (install this in Joomla) |
| `com_securityguard.zip` | Component only |
| `plg_system_securityguard.zip` | System plugin only |

The build uses the `zip` tool when available and falls back to Python, so it runs on Linux,
macOS and Windows alike.

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

- **CI** lints PHP (`php -l`), validates XML manifests, and builds the packages on every
  push and pull request.
- **Release** is triggered by pushing a `vX.Y.Z` tag: it verifies the tag matches the
  manifest version, builds the zips, publishes a GitHub Release, and updates the Joomla
  update server on GitHub Pages.

## Contributing

See [docs/](docs/) for development and release documentation. Issues and pull requests are
welcome.

## License

[GNU GPL v2 or later](LICENSE) © pasichDev
