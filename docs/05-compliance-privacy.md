# 05 — Compliance & Privacy

> A security agent is, by nature, a deep monitoring tool. To be deployable in
> the EU and other regulated markets, privacy must be engineered in — not bolted
> on. *(This document is engineering guidance, not legal advice; validate with
> counsel and your DPO.)*

## 1. Why this is hard
The very telemetry that powers detection — file paths, command lines, URLs,
IP addresses, usernames, and sometimes file samples — frequently **contains
personal data** under GDPR (Art. 4). File paths leak usernames and document
titles; command lines leak credentials/queries; IPs are personal data
(*Breyer*). The agent also constitutes **employee monitoring**, which triggers
additional regimes (below). Privacy-by-design (Art. 25) is mandatory.

## 2. Roles & lawful basis

| Aspect | Position |
|---|---|
| **Controller / processor** | The **deploying enterprise is the controller**; the vendor is typically a **processor** acting on documented instructions. Sign a **Data Processing Agreement (Art. 28)** with every customer. |
| **Lawful basis** | **Legitimate interest (Art. 6(1)(f))** — network & information security is expressly recognized as a legitimate interest in **Recital 49**. Document a **Legitimate Interest Assessment (LIA)** balancing security need vs. employee privacy. |
| **Special-category data** | Not intentionally processed; redaction + minimization reduce incidental capture (Art. 9 risk). |

## 3. Privacy-by-design controls (the core of the design)

### 3.1 Data minimization (Art. 5(1)(c))
- Collect **only what detection/response needs**. Default telemetry =
  security-relevant metadata, **not** file contents.
- **Tiered telemetry levels** the customer controls:
  `Minimal` (verdicts + critical alerts) → `Standard` (security metadata) →
  `Full` (rich EDR event stream). Customer chooses; documented per tier.

### 3.2 Pseudonymization & anonymization (Art. 4(5), Art. 25)
- **Hash/tokenize identifiers** (device, user) where the raw value isn't needed
  for the security purpose.
- **Path & command-line redaction:** strip user profile names, scrub
  obvious secrets/tokens, and offer regex-based redaction rules so customers can
  remove PII before anything leaves the endpoint.
- Aggregate where possible (counts/prevalence rather than raw events).

### 3.3 Sample submission = the highest-risk feature
Uploading suspicious **files** can exfiltrate personal/confidential documents.
Therefore:
- **Off / opt-in by default for content**; metadata-only by default.
- **On-endpoint pre-screening + redaction**; flag/skip likely-sensitive
  document types per policy.
- Per-policy controls, audit log of every submission, and contractual coverage
  in the DPA.
- Option to keep samples **on-prem** (customer-hosted sandbox) for the strictest
  customers.

### 3.4 Data residency & international transfers (Ch. V)
- **Regional cloud:** EU customers' data stays in **EU data centers**; data
  residency is a deployment-time choice.
- Where transfer is unavoidable, use **SCCs / adequacy** and document transfer
  impact assessments. Sub-processors disclosed and flowed-down.

### 3.5 Security of processing (Art. 32)
- **Encryption in transit** (mTLS, [docs/03](docs/03-secure-updates.md)) and
  **at rest**; strict access controls + audit logging on the backend;
  tenant isolation.

### 3.6 Storage limitation & retention (Art. 5(1)(e))
- **Configurable retention** with sane security defaults (e.g., raw EDR events
  30–180 days; alerts/IOC longer for investigation). Automatic deletion at term.

### 3.7 Data-subject rights
- Backend tooling to support **DSARs, access, rectification, and erasure**,
  balanced against the security record-keeping exemptions. Because data is
  tenant-scoped and identifiers are pseudonymized, the controller can locate and
  act on a subject's records.

### 3.8 Transparency
- Clear documentation of **exactly what each telemetry tier collects**, why,
  and retention — for the customer's own privacy notices and **DPIA**.

## 4. DPIA (Art. 35)
Large-scale, systematic monitoring of behavior almost certainly requires a
**Data Protection Impact Assessment**. We provide a **DPIA template/pack** so
customers can complete theirs quickly, documenting purposes, data categories,
necessity/proportionality, risks, and mitigations (the §3 controls).

## 5. Beyond GDPR — local & sectoral mandates
- **Employee/works-council law:** in several EU states (e.g., Germany), workplace
  monitoring tools require **works-council co-determination**; in France, CNIL
  guidance applies. Surface this in deployment docs — it's a customer obligation
  but a sales blocker if ignored.
- **Other regimes to map:** UK GDPR/DPA 2018, **CCPA/CPRA** (US-CA), **LGPD**
  (Brazil), **PIPEDA** (Canada), **APPI** (Japan), plus sectoral (HIPAA, PCI-DSS,
  FedRAMP for US public sector, **NIS2** for EU critical entities).

## 6. Certifications & assurance (roadmap)
| Certification | Why |
|---|---|
| **ISO/IEC 27001** | Baseline ISMS; table stakes for enterprise procurement |
| **SOC 2 Type II** | Operating-effectiveness evidence for US enterprise |
| **ISO/IEC 27701** | Privacy extension to 27001 (PIMS) |
| **Common Criteria / FIPS 140-3** | Government/regulated sales; FIPS for the crypto modules |
| **FedRAMP** (if US public sector) | Federal cloud authorization |

## 7. Privacy engineering checklist
- [ ] DPA template (processor terms) ready for customers
- [ ] LIA documented for security telemetry
- [ ] Telemetry tiers implemented; **content collection opt-in by default**
- [ ] On-endpoint redaction (paths, command lines, secrets) + customer rules
- [ ] Identifier pseudonymization/tokenization
- [ ] EU data residency option; transfer mechanism (SCCs) documented
- [ ] Configurable retention + automatic deletion
- [ ] DSAR / erasure tooling in backend
- [ ] Per-tier data-collection documentation published
- [ ] DPIA template shipped to customers
- [ ] Sub-processor list maintained & disclosed
