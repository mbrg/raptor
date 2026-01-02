# Evidence Request 001

## Summary

The hypothesis (hypothesis-001.md) identifies critical evidence gaps that prevent HIGH confidence conclusions. The following evidence collection would enable definitive answers to the research questions.

---

## Missing Evidence Items

### 1. npm Registry Audit Data

- **Need**: Publisher identity for @vietmoney/react-big-calendar package
- **Source**: npm registry (requires privileged access or public disclosure)
- **Agent**: Manual outreach to npm security team or FOIA-equivalent request
- **Query**: "Who published @vietmoney/react-big-calendar versions containing bun_installer.js?"

**Reason**: Cannot determine if B611 = package publisher without this data. This is the critical attribution gap.

**Questions This Will Answer**:
- Is B611 the threat actor or a victim of account takeover?
- Was the npm account compromised or purpose-built?
- What email address is associated with publishing?

---

### 2. Passive DNS Historical Records for m.fasterxml.org

- **Need**: DNS resolution history for m.fasterxml.org
- **Source**: Passive DNS databases (SecurityTrails, PassiveTotal, Farsight DNSDB)
- **Agent**: oss-investigator-gh-api-agent (extend to DNS sources) or manual query
- **Query**: "Historical A/AAAA/CNAME records for m.fasterxml.org 2025-09-01 to 2026-01-01"

**Reason**: The C2 domain claim is flagged as potential false positive. No Wayback archives exist. Passive DNS would confirm if the domain ever resolved to infrastructure.

**Questions This Will Answer**:
- Did m.fasterxml.org ever resolve to an IP address?
- What hosting infrastructure was used?
- When was the domain active vs. parked?

---

### 3. Malware Sample Acquisition

- **Need**: Actual malicious package tarball or extracted source code
- **Source**:
  - npm security team (may have preserved samples)
  - Security researcher collections (Socket.dev, Snyk, Phylum)
  - VirusTotal (if uploaded)
- **Agent**: Manual outreach or VirusTotal API query
- **Query**: "Sample of @vietmoney/react-big-calendar with bun_installer.js"

**Reason**: Cannot validate file-based IOCs (hashes, obfuscated filenames, TruffleHog patterns) without the actual malware.

**Questions This Will Answer**:
- What are the actual file hashes for v3 IOCs?
- Does code actually contact m.fasterxml.org?
- Is there evidence of LLM-assisted coding?
- What exact credential patterns are harvested?

---

### 4. Blockchain Transaction Analysis

- **Need**: Wallet addresses and transaction hashes for claimed thefts
- **Source**:
  - Trust Wallet incident report (if public)
  - Blockchain explorers (Etherscan, BscScan, etc.)
  - Chainalysis/Elliptic reports
- **Agent**: Manual research or blockchain API queries
- **Query**: "Transactions associated with Shai Hulud v1/v2/v3 theft claims"

**Reason**: The $50M (v1) and $8.5M (v3) theft claims are unverified. Blockchain is immutable evidence.

**Questions This Will Answer**:
- Is the $50M figure accurate or estimated?
- What wallet addresses received stolen funds?
- Can we trace funds to exchanges (potential attribution)?
- Is Dec 31, 2025 Trust Wallet date accurate?

---

### 5. hoquocdat Account Provenance

- **Need**: Full history of @hoquocdat npm account
- **Source**: npm registry, GitHub API for linked account
- **Agent**: oss-investigator-gh-api-agent
- **Query**: "GitHub user hoquocdat - account creation, activity history, linked npm account"

**Reason**: Web Intel claims account was "dormant 4 years before compromise." This is a key indicator of account takeover vs. sleeper account.

**Questions This Will Answer**:
- When was the account created?
- What was the last legitimate activity before compromise?
- Was there a password reset or session anomaly?
- Is this a compromised legitimate developer or a purpose-built account?

---

### 6. Unit42 Report Methodology

- **Need**: Technical appendix or methodology disclosure from Unit42 report
- **Source**: Palo Alto Networks Unit42 (published Dec 16, 2025)
- **Agent**: Manual outreach or FOIA-equivalent
- **Query**: "Methodology for LLM-assisted code claim and $50M theft figure"

**Reason**: Key claims in threat intel are unverifiable without methodology disclosure.

**Questions This Will Answer**:
- How was LLM assistance detected in code?
- What blockchain analysis supported $50M figure?
- How were 1,195 organizations counted?

---

## Priority Ranking

| Evidence Item | Impact on Hypothesis | Feasibility |
|---------------|---------------------|-------------|
| npm Registry Audit | CRITICAL (attribution) | LOW (requires npm cooperation) |
| Malware Sample | HIGH (IOC validation) | MEDIUM (security researchers may have) |
| Passive DNS | HIGH (C2 verification) | HIGH (commercial services available) |
| Blockchain Analysis | MEDIUM (theft verification) | HIGH (public data) |
| hoquocdat Account | MEDIUM (victim/actor clarity) | HIGH (GitHub API) |
| Unit42 Methodology | LOW (meta-analysis) | LOW (unlikely to disclose) |

---

## Recommended Next Steps

1. **Immediate**: Query Passive DNS for m.fasterxml.org via SecurityTrails or similar
2. **Immediate**: Query GitHub API for hoquocdat user profile and activity
3. **Short-term**: Request malware sample from Socket.dev or Phylum research teams
4. **Medium-term**: Analyze blockchain for Trust Wallet heist transactions
5. **Long-term**: Engage npm security team for audit data

---

*Evidence request generated: 2026-01-02*
*Priority: npm audit data and passive DNS are most critical for attribution confidence*
