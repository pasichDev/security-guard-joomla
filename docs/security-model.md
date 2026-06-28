# Security model: backend trust, brute-force, and lockout recovery

This page documents how the system plugin (`plg_system_securityguard`) decides
who to block, how it protects the login form, and — importantly — how it avoids
locking out the very administrator who runs the site.

## Request flow (`onAfterInitialise`)

For every front-end request the plugin runs, in order:

1. **Emergency bypass** — if `?sg_pass=<token>` matches the configured
   `bypass_token`, the current IP's block is cleared and the request passes.
2. **Whitelist** — loopback (`127.0.0.1`, `::1`), the manual prefix list, and
   auto-trusted Super User IPs pass with no further checks.
3. **Backend trust** — requests to the Joomla `/administrator` application skip
   all offensive heuristics (see below). An existing block is still honoured.
4. The usual WAF chain (verified bots, existing blocks, honeypot, fake-bot,
   user-agent, geo-block, PHP-probe burst, attack patterns, rate limit,
   behavior scoring, traffic tracking).

## Backend trust — why the admin no longer self-blocks

The Joomla backend is already password-protected, and a logged-in admin clicking
around fires many `/administrator/index.php` requests (page + AJAX modules +
quickicons). Running the offensive heuristics against that traffic used to
self-block the admin — most often via the **PHP-probe burst** detector (5 `.php`
hits in 10 s) or by accumulating **behavior score** on the `/administrator` path.

The plugin now treats the administrator application as trusted: it never creates
a block from backend browsing. Admin-login brute force is handled separately (see
below), and an already-blocked IP is still denied the login form.

## Brute-force login protection

`onUserLoginFailure` counts failed logins per IP (backend **and** frontend) in
`#__securityguard_rate` using a `bf:` marker. Once `bruteforce_threshold`
failures occur within `bruteforce_window`, the IP is blocked through the normal
WAF path with the standard escalation (1 h → 24 h → 7 d → 30 d). A blocked IP
then receives an honest **429 “Too many failed login attempts”** page instead of
a silent 404.

A legitimate admin never trips this, because they don't accumulate failed
logins — only successful ones.

## Staying out of your own jail

Three independent safety nets, any one of which is enough:

- **Auto-trust Super User IP** (`trust_superadmin`, default on). On a successful
  Super User login, that IP is remembered as trusted for `trust_superadmin_days`
  (default 7) in `#__securityguard_whitelist` (description `sg-auto`), and any
  active block on it is cleared. TTL-limited and auto-cleaned.
- **Emergency bypass token** (`bypass_token`). Set a long random secret, then
  visit `https://yoursite/?sg_pass=<secret>` from the locked-out machine to clear
  your own block instantly — no database access required. Empty = disabled.
- **“Unblock my IP”** button on the admin *Blocks* view, which also shows your
  current IP address. Clears the block (and behavior score) for that IP.

## Whitelist semantics

`whitelist_ips` is a newline/comma-separated list of IP **prefixes** (trailing
dot = subnet, e.g. `203.0.113.`). A whitelisted IP bypasses **all** checks and is
never blocked. Loopback is always trusted implicitly. The default is empty —
add your own office/home prefix if you want a permanent bypass.

> Note: the legacy “Restrict /administrator to whitelist” option was removed. It
> defaulted to on and shipped with non-local default IPs, which locked admins out
> of `/administrator` with a 404 on a fresh install. Backend trust plus
> brute-force protection replace it.
