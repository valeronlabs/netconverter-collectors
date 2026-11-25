# FMC importer changes

## [2.4.0] — 2026-10-20

Publish the private engine importer at commit c90c4a62e (FMC-FEED-KIND-AND-ZONE-MODES).

- URL lists are created as Security Intelligence URL feeds (`object/siurlfeeds`), the same way
  network feeds are. Before, the converter emitted URL lists as network feeds.
- Domain lists are not posted: FMC refuses DNS feeds over REST (HTTP 405), so the converter
  declares them as a manual step instead.
- A missing feed collection (HTTP 404) names the feed kind (Network or URL) in its message.

Verified with focused mocked-API tests and an FMC 7.6.5 lab response for the DNS-feed refusal.
This publication does not claim a new device deployment.

## [2.2.1] — 2026-10-04

Publish the reviewed private engine importer from commit 6e3b59f6a715d7a6707ade107a43ff6493720f64 (the importer bytes originate in the preceding FMC fixes).

- Refresh an invalidated FMC authentication session with a bounded retry.
- Preserve per-policy rule placement and ordering; make policy reuse explicit.
- Resolve object references and expose incompatible same-name collisions.
- Surface unsupported source/target matches and missing required FMC objects.
- Keep dry-run read-only and report failures without suggesting an unsafe plain rerun.

The current importer has focused mocked-API regression coverage and earlier FMC 7.6.5 native import evidence. This publication does not claim a new device deployment or packet validation.
