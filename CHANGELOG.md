# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Public repository layout: source unpacked into `src/`.
- `build/build.sh` to assemble installable packages (zip tool with Python fallback).
- GitHub Actions CI (PHP lint, XML validation, package build) and release automation.
- Joomla update server (`updates.xml`) published to GitHub Pages for in-admin auto-updates.
- Bilingual README (English + Ukrainian) and English documentation under `docs/`.

## [1.3.12] - 2026-06-17

Last release published before the project was moved to this public repository. Includes the
full WAF feature set: WAF, Honeypot, behavior scoring, live dashboard, Grafana-style traffic
monitor, DDoS detection and geo-tracking.

[Unreleased]: https://github.com/pasichDev/security-guard-joomla/compare/v1.3.12...HEAD
[1.3.12]: https://github.com/pasichDev/security-guard-joomla/releases/tag/v1.3.12
