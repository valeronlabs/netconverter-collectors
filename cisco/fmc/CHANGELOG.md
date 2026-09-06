# Changelog — Cisco FMC (`cisco/fmc/`)

All notable changes to the FMC collector and its HTML builder. Collect and HTML
share one `__version__`. Versions are independent of other collectors and of
the NetConverter.local appliance.

## [2.3.2] — 2026-09-06

- Preserve native policy assignments in `policy-assignments.json`, including
  policy and target type/ID fields even when device records omit ACP/NAT links.
- Record separate per-endpoint `collection-evidence.json`: pagination totals,
  requested offsets, timestamps, success/empty/partial/error, and route-family
  fallback outcomes. Native device, object, assignment and rule JSON is unchanged.
- Follow server-shortened pages and same-origin/same-endpoint next offsets;
  reject repeated/skipped pages, changing totals and redirects. Failed later pages
  remain explicitly partial. Bound collection by page and item limits.
- Save successfully empty rule arrays. Completeness uses recorded FMC totals for
  each endpoint/policy, never a captured count presented as an independent total.
  HTTP errors do not establish that a feature is unsupported by the platform.
- HTML generation works with core 1.1.2, including empty bundles; CSV actions
  explicitly export the filtered rows. An older core must be upgraded with FMC.

## [2.3.1] — 2026-09-05

- Collect IPv6 static routes independently of IPv4 routes. A populated IPv4 table no longer suppresses IPv6 collection; the legacy IPv4 endpoint remains a fallback only.
- HTML viewer version updated to 2.3.1. Synthetic dual-stack and IPv4-fallback regression coverage added.

## [2.3.0] — 2026-06-22
### Added
- Per-run completeness self-audit (`completeness.csv`) + a Completeness page
  reconciling captured vs live FMC totals; API-blocked endpoints labelled so a
  `0` is never mistaken for data loss.
- One-click Excel / CSV export on every browse/rule table.
- Applications & URLs "in use" L7 view: L7 objects referenced by access rules,
  cross-referenced to those rules + catalog risk/type.
- HTML viewer **v2.3.0** badge (`viewer_version`) on every generated page.
### Fixed
- Token auth now auto-retries transient `401`/`429`/timeout/`5xx` with backoff
  (sandbox/lab FMC resilience).
### Known limitations
- DNS rule bodies are not exposed by the FMC REST API on current versions
  (`/dnspolicies/{id}/dnsrules` -> `404`); shown as `api_blocked` in the audit.
  NAT, access, and L7 app/URL references are captured in full.
