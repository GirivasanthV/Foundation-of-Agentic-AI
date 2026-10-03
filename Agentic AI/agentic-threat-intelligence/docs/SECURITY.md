# Security boundaries

This repository is safe-by-default and uses live/local evidence only; it does not generate synthetic provider results.

## Current safeguards

- Response actions are simulated.
- Literal private, loopback, link-local and reserved IP targets are rejected.
- Localhost and `.local` URLs are rejected.
- Embedded URL credentials are rejected.
- API keys stay server-side and are excluded from version control.
- Blocking recommendations require analyst approval.
- Browser-extension requests require a shared development token.
- Extension scans have a duplicate-URL cooldown and configurable domain exclusions.
- File bytes remain local; only SHA-256 and basic metadata are transmitted.

## Screenshot capture safeguards

- Chromium runs as an unprivileged user in a disposable container context.
- The destination is resolved and checked before navigation.
- Every browser request and redirect is revalidated; private, loopback, link-local and reserved targets are aborted.
- Each capture uses an isolated context without analyst cookies or profiles.
- Navigation, settling and evidence-size limits are configured.

Production deployments should additionally enforce the same private/metadata-network denial at the container egress layer.

The browser extension captures the user's current visible tab, so its settings page must clearly disclose this behavior. Sensitive domains should be excluded, and enterprises should distribute a managed exclusion policy.

## Required before real blocking

- Microsoft Entra ID authentication and role-based authorization.
- Signed approval records and immutable audit retention.
- Idempotent response actions.
- Automatic expiry and rollback of blocklist entries.
- Separate credentials for each response integration.
- Two-person approval for broad network controls.
