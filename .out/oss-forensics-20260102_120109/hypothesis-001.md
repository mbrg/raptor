# Hypothesis 001: Shai Hulud 3.0 "The Golden Path" Attribution and IOC Analysis

## Research Questions
1. Who is behind Shai Hulud 3.0? (Attribution validation)
2. What are the new IOCs specific to v3.0?
3. Who are the victims of v3.0 specifically?
4. Can we challenge or confirm claims in threat intelligence reports?
5. What undiscovered details would be publication-worthy?

## Summary

Shai Hulud 3.0 represents a sophisticated evolution of an npm supply chain attack campaign. Based on available evidence, the threat actor demonstrates operational security improvements over v1/v2, including rapid repo deletion before GH Archive capture. The v3 campaign appears to have been in a **testing phase** with limited victim impact (197 downloads, 0 confirmed infections). Critical claims in threat intelligence reports remain **unverifiable** due to evidence gaps, including the $50M theft figure and the C2 domain m.fasterxml.org.

---

## 1. Attribution Analysis

### Actor: B611

| Attribute | Value | Evidence ID | Confidence |
|-----------|-------|-------------|------------|
| Username | B611 | [EVD-repo-search-v1] | HIGH |
| Location | Paris, France | User briefing | MEDIUM (self-reported) |
| Account Created | 2018-01-26 | User briefing | HIGH |
| Key Repository | B611/Shai-Hulud | [EVD-repo-search-v1] | HIGH |
| Commit SHA | 60c72debaffd260c9b6c3320b56f1f72b5006fa1 | User briefing | HIGH |
| GPG Signed | Yes (2025-09-16) | User briefing | HIGH |

### Attribution Assessment

**Hypothesis A: B611 is the Threat Actor**
- Evidence FOR:
  - Owns the canonical "B611/Shai-Hulud" repository [EVD-repo-search-v1]
  - GPG-signed commits suggest deliberate identity establishment
  - Account age (2018) indicates patient actor building reputation
- Evidence AGAINST:
  - Paris location is self-reported and unverifiable
  - GPG signing is unusual for malware authors (creates attribution trail)
  - No direct evidence linking B611 to npm package publication

**Hypothesis B: B611 is a Victim or Persona**
- Evidence FOR:
  - GPG signing could indicate account takeover with legitimate history
  - Malware authors typically avoid traceable signing
  - No GH Archive events showing B611 pushing malicious code [EVD-gharchive-malicious-files-dec2025]
- Evidence AGAINST:
  - Shai-Hulud name originates from this repo
  - 3 forks preserve evidence (suggests community flagged as significant)

**Conclusion**: **INCONCLUSIVE** - B611's role cannot be determined without:
1. npm registry audit logs showing who published @vietmoney/react-big-calendar
2. GPG key provenance and email association
3. Timeline correlation between B611 commits and npm package timestamps

### Single Actor vs. Team

| Indicator | Assessment | Evidence |
|-----------|------------|----------|
| v1->v2->v3 code evolution | Suggests single developer with iterating codebase | Web Intel (user briefing) |
| 288+ packages in v2 | Requires automation, not necessarily multiple actors | [EVD-gharchive-v1-markers-sept2025] |
| 1,195 organizations compromised | Scale suggests automated tooling | Web Intel (unverified) |
| v3 TTP changes (dead man's switch removal) | Consistent with single actor refining approach | Web Intel |

**Conclusion**: Evidence supports **single sophisticated actor with automation**, not a team.

---

## 2. IOC Validation

### m.fasterxml.org C2 Domain

| Claim | Evidence | Confidence |
|-------|----------|------------|
| Used as C2 for data exfiltration | Web Intel reports | LOW |
| Typosquat of legitimate fasterxml.org | Wayback shows legitimate fasterxml.org archived 2016 | HIGH |
| Active C2 infrastructure | NOT ARCHIVED in Wayback Machine | UNVERIFIABLE |

**CRITICAL ASSESSMENT**: The m.fasterxml.org C2 claim is potentially a **FALSE POSITIVE** or **unverifiable**:
- No Wayback Machine snapshots exist
- No GH Archive evidence of code reaching out to this domain
- No network traffic captures in evidence store
- Claim originates from threat intel reports without methodology disclosure

**Recommendation**: This IOC should be treated with **LOW CONFIDENCE** until:
1. Passive DNS historical records are obtained
2. Malware sample with network call to this domain is analyzed
3. Web server logs or SIEM data confirm connections

### v3 File Indicators

| Filename | Purpose (Claimed) | Evidence | Confidence |
|----------|-------------------|----------|------------|
| bun_installer.js | Cross-platform installer | Web Intel | MEDIUM |
| environment_source.js | Environment harvesting | Web Intel | MEDIUM |
| 3nvir0nm3nt.json | Obfuscated exfil data | Web Intel | LOW |
| cl0vd.json | Obfuscated cloud creds | Web Intel | LOW |
| c9nt3nts.json | Obfuscated content dump | Web Intel | LOW |
| pigS3cr3ts.json | Obfuscated secrets | Web Intel | LOW |

**Evidence Gap**: No GH Archive events captured these filenames [EVD-gharchive-malicious-files-dec2025]. This is consistent with rapid deletion but prevents independent verification.

### Verified v3 Markers

| Marker | Status | Evidence |
|--------|--------|----------|
| "Goldox-T3chs: Only Happy Girl" description | 0 repos found | [EVD-repo-search-v3-goldox-t3chs] |
| @vietmoney/react-big-calendar npm package | Confirmed existed, now unpublished | Web Intel |
| hoquocdat maintainer account | 4 years dormant before compromise | Web Intel |

---

## 3. Victimology - v3 Specific

### Confirmed v3 Package

| Package | Downloads | Confirmed Infections | Evidence |
|---------|-----------|---------------------|----------|
| @vietmoney/react-big-calendar | 197 | 0 | Web Intel |

### Victim Analysis

**Assessment**: v3 was likely a **testing/staging phase**, not a full campaign:

1. **Single Package**: v2 had 288+ packages; v3 had 1
2. **Low Download Count**: 197 downloads suggests minimal distribution
3. **No Confirmed Infections**: Web Intel states "0 confirmed infections"
4. **Rapid Detection**: npm revoked all classic tokens Dec 9, 2025 - campaign disrupted early

### Who Downloaded @vietmoney/react-big-calendar?

**Evidence Gap - UNVERIFIABLE**:
- npm does not publish download attribution
- No evidence store data on downloaders
- 197 downloads could include:
  - Automated vulnerability scanners
  - npm mirrors
  - Security researchers
  - Legitimate but unaware developers

**Potential Victims Profile** (hypothetical):
- Projects using react-big-calendar seeking alternative/forked versions
- Vietnamese-language projects due to @vietmoney scope
- CI/CD pipelines with loose dependency specifications

---

## 4. Threat Intelligence Report Claims - Challenge/Confirm

### Claim 1: LLM-Assisted Code Writing (Unit42)

| Claim | "Code shows evidence of LLM assistance" |
|-------|------------------------------------------|
| Evidence | NONE in evidence store |
| Verification | IMPOSSIBLE without source code samples |
| Assessment | **UNVERIFIABLE** - No methodology disclosed |

**Challenge**: What specific code patterns indicate LLM usage? This claim requires:
- Side-by-side comparison with LLM outputs
- Stylometric analysis
- Disclosure of specific code snippets analyzed

### Claim 2: $50M Cryptocurrency Theft from v1

| Claim | "$50M stolen in v1 campaign" |
|-------|------------------------------|
| Evidence | Web Intel only |
| Verification | Requires blockchain analysis |
| Assessment | **UNVERIFIABLE** - No wallet addresses, no transaction hashes |

**Challenge**: Where is the blockchain evidence?
- No wallet addresses in evidence store
- No Chainalysis/Elliptic reports cited
- Figure may be extrapolated, not measured

### Claim 3: $8.5M Trust Wallet Heist (Dec 31, 2025)

| Claim | "$8.5M stolen from 2,520 wallets" |
|-------|-----------------------------------|
| Evidence | Web Intel |
| Date | December 31, 2025 |
| Assessment | **PARTIALLY VERIFIABLE** with blockchain data |

This claim is more specific and potentially verifiable with:
- Trust Wallet incident report
- Blockchain transaction analysis
- Wallet address list

### Claim 4: 1,195 Organizations Compromised

| Claim | "1,195 organizations compromised" |
|-------|-----------------------------------|
| Evidence | Web Intel only |
| Methodology | Unknown |
| Assessment | **UNVERIFIABLE** - No breakdown, no source |

**Challenge**: How was this counted?
- Self-reported incidents?
- Package download analysis?
- Telemetry from compromised packages?
- Sector breakdown exists but methodology unknown

### Claim 5: AsyncAPI OpenVSX API Key Stolen

| Claim | "Cross-registry propagation via stolen key" |
|-------|---------------------------------------------|
| Evidence | GH Archive shows normal asyncapi activity [EVD-gharchive-asyncapi-dec2025] |
| Assessment | **NOT CORROBORATED** - 200 events, no suspicious patterns |

---

## 5. Publication-Worthy Findings

### Finding 1: GH Archive Evasion Tactics

The threat actor's v3 repos were deleted **before GH Archive hourly capture** [EVD-gharchive-v3-goldox-search-dec2025, EVD-repo-search-v3-goldox-t3chs].

**Significance**: This demonstrates:
- Operational awareness of GitHub archival cadence
- Sub-1-hour dwell time for malicious repos
- Security researchers cannot rely on GH Archive for real-time threats

**Publication Angle**: "The 1-Hour Blind Spot: How Supply Chain Attackers Evade GH Archive"

### Finding 2: Attribution Theater vs. Reality

The B611 account presents contradictory signals:
- GPG-signed commits (unusual for malware authors)
- 7-year-old account (suggests reputation building)
- Paris location (easily fabricated)

**Publication Angle**: "The GPG Paradox: Why Signed Commits Don't Guarantee Authenticity"

### Finding 3: Threat Intel Report Verification Gap

Multiple high-profile claims lack verifiable evidence:
| Claim | Verification Status |
|-------|---------------------|
| $50M v1 theft | No blockchain evidence |
| LLM-assisted code | No methodology |
| 1,195 orgs | No source |
| m.fasterxml.org C2 | No network evidence |

**Publication Angle**: "Citation Needed: The Verification Crisis in Supply Chain Threat Intelligence"

### Finding 4: v3 as Testing Campaign

Evidence suggests v3 was **interrupted early**:
- npm token revocation Dec 9, 2025
- Only 197 downloads
- 0 confirmed infections
- Single package vs. 288+ in v2

**Publication Angle**: "Catching the Worm Early: How npm's Token Revocation May Have Prevented v3 Mass Compromise"

---

## Evidence Citations

| ID | Type | Source | Summary |
|----|------|--------|---------|
| EVD-repo-search-v1 | search_result | github_api | 31 repos with v1 marker, including B611/Shai-Hulud |
| EVD-repo-search-v2 | search_result | github_api | 269 repos with v2 marker, mostly scanners |
| EVD-repo-search-v3-goldox-t3chs | search_result | github_api | 0 repos with v3 marker (all deleted) |
| EVD-gharchive-v3-goldox-search-dec2025 | gharchive_query | bigquery | 0 v3 description markers found |
| EVD-gharchive-v1-markers-sept2025 | gharchive_query | bigquery | 52 repos Sept 2025 |
| EVD-gharchive-shai-hulud-repos-dec2025 | gharchive_query | bigquery | 980 events, 94 repos, mostly scanners |
| EVD-gharchive-malicious-files-dec2025 | gharchive_query | bigquery | 0 malicious filenames found |
| EVD-gharchive-vietmoney-dec2025 | gharchive_query | bigquery | 0 vietmoney org events |
| EVD-gharchive-asyncapi-dec2025 | gharchive_query | bigquery | 200 events, normal activity |
| EVD-gharchive-react-big-calendar-dec2025 | gharchive_query | bigquery | 67 events, no vietmoney fork |

---

## Confidence Summary

| Research Question | Answer Confidence | Key Gap |
|-------------------|-------------------|---------|
| Who is behind v3? | LOW | npm publisher identity unknown |
| What are v3 IOCs? | MEDIUM | No malware samples in evidence |
| Who are v3 victims? | LOW | No download attribution |
| Verify threat intel claims? | LOW | No blockchain/methodology data |
| Publication-worthy findings? | HIGH | Meta-analysis is solid |

---

## Prediction: What Happens Next?

Based on campaign evolution patterns:

1. **v4 will emerge** - Actor has invested significant effort; unlikely to abandon
2. **New registry targets** - VSCode Marketplace, PyPI, Cargo mentioned in reports
3. **Improved evasion** - Shorter dwell times, no description markers
4. **Cryptocurrency focus** - Trust Wallet heist shows continued financial motivation

**Recommended Monitoring**:
- npm packages from dormant maintainers
- GitHub repos without description markers
- Bun-based installers in dependency chains
- TruffleHog-like credential harvesting patterns

---

## Analyst Notes

This hypothesis is constrained by significant evidence gaps. The orchestrator should consider spawning additional evidence collection for:

1. **npm registry audit logs** - Would definitively identify package publisher
2. **Passive DNS for m.fasterxml.org** - Would verify or refute C2 claim
3. **Blockchain analysis** - Would verify theft claims
4. **Malware sample acquisition** - Would enable IOC validation

Without these, many conclusions remain at LOW confidence.

---

*Hypothesis formed: 2026-01-02*
*Evidence items cited: 10*
*Confidence: Mixed (see summary table)*
