# Detection Content

Seed/sample detection content for the Phase 1 MVP. **In production this content
is authored by Threat Research and shipped through the signed, staged TUF update
channel** described in [docs/03-secure-updates.md](../docs/03-secure-updates.md)
— it is not hand-edited in the repo at runtime.

```
signatures/
├── hashes/
│   └── baseline.hashdb     # known-bad SHA-256 -> Family.Name
└── yara/
    ├── eicar.yar           # standardized test vector
    └── webshells.yar       # illustrative high-fidelity rules
```

## Hash database format
```
# comment
<sha256-hex>  <Family.Name>
```
Parsing is strict (a malformed hash aborts the load with a line number) so a
corrupt database is caught at startup rather than silently weakening detection.

## YARA authoring standard (high-fidelity discipline)
Every shipped rule must:
1. **Carry metadata:** `author`, `description`, `severity`
   (`low|medium|high|critical`), `reference` (prefer a MITRE ATT&CK technique),
   and `date`. The engine reads `severity` to set the detection severity.
2. **Minimize false positives:** prefer tight, anchored conditions; bound with
   `filesize`; require multiple corroborating strings; avoid single generic
   tokens. A noisy rule is worse than no rule.
3. **Be validated before shipping:** the CI test
   `shipped_signature_content_compiles_and_detects` compiles every rule and
   asserts EICAR is detected while a benign file is not. Production additionally
   gates on a large clean-file corpus (see
   [docs/02-detection-engine.md](../docs/02-detection-engine.md) §8).

> Severities here are advisory inputs to the verdict/response policy; they do
> not by themselves trigger destructive action in the MVP (scan-and-report).
