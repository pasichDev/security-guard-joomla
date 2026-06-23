# Contributing

Thanks for helping improve Security Guard for Joomla!

## Getting started

```bash
npm install          # installs husky + commitlint and the release tooling
bash build/build.sh  # build the installable package locally
```

## Commit messages

This project uses **Conventional Commits** and **automated releases** — the version,
changelog and GitHub Release are produced from your commit messages. Please read
[docs/commit-convention.md](docs/commit-convention.md) before committing.

Quick reference:

```
feat(waf): add rate-limit rule for repeated 404 probes
fix(component): enforce core.manage on destructive tasks
docs: clarify update-server setup
```

A local git hook and the **Commit Lint** CI job validate every commit.

## Pull requests

- Target the `main` branch.
- Keep changes focused; one logical change per PR.
- Make sure CI is green (PHP lint, XML validation, build, commit lint).

## Releasing

Maintainers don't tag releases by hand. Merging conventional commits to `main` triggers
semantic-release, which bumps the manifests, updates the changelog, and publishes the
release. See [docs/release.md](docs/release.md).
