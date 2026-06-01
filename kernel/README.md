# `kernel/` — Kernel sensor (Phase 2, not yet implemented)

Reserved for the kernel-mode sensor. **Intentionally empty in Phase 1** — we
prove the engine in user mode first; a kernel bug on a production machine is a
non-starter (see [docs/01 §8](../docs/01-core-architecture.md)).

Planned contents (Phase 2):
- `minifilter/` — file-system minifilter (real-time file protection, C/KMDF)
- `callbacks/` — process/thread/image, registry, object callbacks
- `elam/` — Early Launch Anti-Malware driver (anchors PPL)
- `wfp/` — network callout driver

Gated on: minifilter altitude allocation + ELAM/PPL entitlement + WHQL
(see [docs/04](../docs/04-deployment-distribution.md), [docs/06](../docs/06-implementation-roadmap.md)).
