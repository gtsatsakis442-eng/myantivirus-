# `cloud/` — Backend services (later phase)

Reserved for the cloud control/data plane: management console, reputation
service, telemetry ingest + lake, EDR/hunting, and the **TUF content
repository**. Not implemented in Phase 1.

Design references:
- Telemetry flow (under review): [docs/07-telemetry-flow.md](../docs/07-telemetry-flow.md)
- Reputation & cloud verdicts: [docs/02 §6](../docs/02-detection-engine.md)
- Secure update repo (TUF/CDN): [docs/03](../docs/03-secure-updates.md)
- Privacy & residency: [docs/05](../docs/05-compliance-privacy.md)
