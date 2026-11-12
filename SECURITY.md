# Security Policy

Security Guard for Joomla is a Joomla 3.10 WAF package (administrator component and system plugin). If you find a security flaw in this package, please report it privately so it can be investigated before the details become public.

## Supported versions

Security fixes are considered for the latest maintained release of Security Guard for Joomla. Older package releases should be updated before reporting an issue. This policy does **not** extend security support to Joomla core or to Joomla 3.10 itself.

## Reporting a vulnerability

**Preferred:** use GitHub's [Report a vulnerability](https://github.com/pasichDev/security-guard-joomla/security/advisories/new) form in the repository's Security / Advisories section.

**Fallback:** contact [apasichnik9@gmail.com](mailto:apasichnik9@gmail.com) directly with a short initial summary. Do not send secrets or production data in the first message; arrange a suitable confidential channel if the report requires them.

Do not post a working exploit, secret, full log, affected live-site URL, or unpatched vulnerability details in a public issue, discussion or pull request.

A useful report includes:

- Affected package version or commit, Joomla/PHP versions, and relevant configuration
- Concise reproduction steps on an environment you own or are authorized to test
- Expected versus observed behavior, impact, and any relevant logs with credentials and personal data removed
- Whether the issue requires unusual permissions or a specific deployment configuration

## Handling reports

I will review actionable reports, attempt to reproduce them and coordinate a fix and disclosure if the issue is confirmed. No guaranteed response or patch deadline is implied. Attribution can be discussed with the reporter.

Please use only your own or explicitly authorized test environment. Vulnerabilities in Joomla core, hosting infrastructure or third-party extensions should also be reported to their respective maintainers.

For a description of this plugin's actual checks and their limitations, see [docs/security-model.md](docs/security-model.md).
