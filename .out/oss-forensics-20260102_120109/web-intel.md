# Shai Hulud 3.0 "The Golden Path" - Web Threat Intelligence Report

**Investigation Date:** January 2, 2026
**Investigator:** RAPTOR OSS-Forensics
**Target:** Shai Hulud 3.0 "The Golden Path" npm supply chain worm

---

## Executive Summary

Shai Hulud 3.0, dubbed "The Golden Path," represents the third major evolution of a sophisticated npm supply chain worm campaign. First discovered on December 29, 2025, this variant was found in the @vietmoney/react-big-calendar package (v0.26.2). Unlike previous waves that achieved massive spread, this variant appears to be a **testing phase** with limited distribution (197 downloads of v0.26.2, no confirmed infections).

**Key Findings:**
- **Attribution:** Highly likely same actor as v1.0 and v2.0 based on access to original source code
- **Impact:** 1,195+ organizations compromised across all campaigns (banks, governments, Fortune 500)
- **Financial Loss:** $8.5 million stolen from Trust Wallet via v2.0
- **Evolution:** Enhanced obfuscation, Windows compatibility, improved error handling
- **Branding Change:** Exfiltration repos now marked "Goldox-T3chs: Only Happy Girl"

---

## Campaign Timeline

### Shai Hulud 1.0 (September 2025)
- **Discovery Date:** September 16, 2025
- **Scale:** 500+ packages compromised, 1,150+ malicious versions
- **First Package:** @ctrl/tinycolor v4.1.1
- **Attribution:** Unknown threat actor, possibly linked to August 27 Nx compromise
- **Impact:** ~$50 million in cryptocurrency theft (CrowdStrike among victims)
- **Response:** CISA issued warning September 23, 2025

**Sources:**
- [Unit42 Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Snyk Incident Report](https://snyk.io/blog/sha1-hulud-npm-supply-chain-incident/)
- [CISA Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)

### Shai Hulud 2.0 "The Second Coming" (November 2025)
- **Discovery Date:** November 24, 2025
- **Scale:** 796 packages, 25,000+ GitHub repos, ~350 unique users
- **Timing:** Launched just before npm's token revocation deadline
- **Repository Marker:** "Sha1-Hulud: The Second Coming"
- **Spread:** Maven ecosystem compromised, AsyncAPI OpenVSX API key stolen
- **Continued Activity:** Renewed spike December 1, 2025 (200+ repos in 12 hours)
- **Financial Impact:** $8.5 million Trust Wallet heist (2,520 wallets)
- **Organizations:** 1,195 confirmed (banks, government, Fortune 500 tech)

**Major Victims:**
- Zapier
- ENS Domains
- PostHog
- Postman
- AsyncAPI
- Browserbase

**Sources:**
- [Wiz Research](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Wiz Aftermath Analysis](https://www.wiz.io/blog/shai-hulud-2-0-aftermath-ongoing-supply-chain-attack)
- [JFrog Analysis](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected)
- [Entro Victimology Report](https://entro.security/blog/shai-hulud-2-0-banks-gov-tech-breach/)
- [SecurityWeek Trust Wallet Heist](https://www.securityweek.com/shai-hulud-supply-chain-attack-led-to-8-5-million-trust-wallet-heist/)

### Shai Hulud 3.0 "The Golden Path" (December 2025)
- **Discovery Date:** December 29, 2025
- **Discoverer:** Charlie Eriksen, Aikido Security
- **Package:** @vietmoney/react-big-calendar v0.26.2
- **Original Publisher:** User "hoquocdat" (March 2021)
- **First Update:** December 28, 2025 (dormant for 4+ years)
- **Downloads:** 698 total, 197 for v0.26.2
- **Impact:** No confirmed infections - appears to be payload testing
- **Repository Marker:** "Goldox-T3chs: Only Happy Girl"

**Sources:**
- [Aikido Discovery](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)
- [The Hacker News](https://thehackernews.com/2025/12/researchers-spot-modified-shai-hulud.html)
- [OX Security Analysis](https://www.ox.security/blog/shai-hulud-3-the-attack-continues/)
- [Upwind Analysis](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm)
- [Snyk Holiday Report](https://snyk.io/blog/shai-hulud-3-0/)

---

## Attribution Analysis

### Threat Actor Profile
**Name:** Unknown (no public attribution)
**Aliases:** Shai-Hulud operator, "The Golden Path" (self-designation)
**Sophistication:** High - demonstrates advanced OPSEC, automation, rapid iteration
**Motivation:** Financial (cryptocurrency theft), credential harvesting
**Theatricality:** Dune-inspired naming ("Shai-Hulud" = sandworms, "The Golden Path")

### Attribution Confidence: MEDIUM-HIGH (Same Actor Across All Campaigns)

**Evidence Supporting Same Actor:**
1. **Source Code Access:** Aikido researchers state the code "was obfuscated again from original source, not modified in place. This makes it highly unlikely to be a copy-cat, but was made by somebody who had access to the original source code for the worm."
2. **Consistent Tradecraft:** TruffleHog integration, GitHub exfiltration, npm self-propagation
3. **Evolutionary Improvements:** Each version addresses weaknesses (Windows support, obfuscation)
4. **Branding Continuity:** Dune references maintained across campaigns

**Evidence Against Attribution:**
- JFrog notes "differences in payload structure and propagation logic" suggest "may involve different threat actors"
- No traditional threat actor indicators (email, language artifacts, infrastructure reuse)

**Sources:**
- [Aikido Attribution Analysis](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)
- [JFrog Threat Assessment](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)

---

## Technical Analysis: Shai Hulud 3.0 "The Golden Path"

### Infection Vector

**Package:** @vietmoney/react-big-calendar v0.26.2
**Mechanism:** Zero-click preinstall script execution

```json
"scripts": {
  "preinstall": "node bun_installer.js"
}
```

**Attack Chain:**
1. Developer runs `npm install @vietmoney/react-big-calendar`
2. npm automatically executes `preinstall` script
3. `bun_installer.js` downloads/installs Bun runtime (evasion technique)
4. Loads `environment_source.js` (obfuscated payload)
5. TruffleHog scans filesystem for secrets
6. Exfiltrates to GitHub repo with "Goldox-T3chs: Only Happy Girl" description

**Sources:**
- [OX Security Technical Breakdown](https://www.ox.security/blog/shai-hulud-3-the-attack-continues/)
- [SC Media Analysis](https://www.scworld.com/brief/more-sophisticated-shai-hulud-malware-emerges)

### Technical Enhancements (v2.0 → v3.0)

| Feature | v2.0 | v3.0 | Impact |
|---------|------|------|--------|
| **Obfuscation** | Moderate | Heavy | Evades static analysis |
| **Windows Support** | Broken | Fixed (bun.exe detection) | Broader attack surface |
| **Error Handling** | Basic | Enhanced (TruffleHog timeout) | Improved reliability |
| **Dead Man's Switch** | Present (wiper) | **REMOVED** | Less destructive |
| **File Names** | setup_bun.js, bun_environment.js | bun_installer.js, environment_source.js | Scanner evasion |
| **Exfil Files** | data.json | 3nvir0nm3nt.json, cl0vd.json, c9nt3nts.json | Improved organization |

**Dead Man's Switch Removal:**
- v2.0 included destructive wiper if GitHub/npm inaccessible
- v3.0 removed this feature - indicates shift toward stealth over destruction

**Sources:**
- [Upwind Technical Comparison](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm)
- [Mondoo Evolution Analysis](https://mondoo.com/blog/shai-hulud-strikes-back-with-v3-0-the-evolution-of-a-potent-and-persistent-npm-supply-chain-worm)

### Credential Harvesting: TruffleHog Integration

**Tool:** TruffleHog (open-source secrets scanner)
**Capabilities:** 800+ secret types detected
**Installation Path:** `~/.truffler-cache/`

**Harvesting Process:**
1. Downloads latest TruffleHog release from GitHub
2. Detects OS and extracts appropriate binary
3. Scans entire home directory for high-entropy strings
4. Targets: API keys, passwords, tokens in `.env`, source code, git history

**Targeted Credentials:**
- **Cloud Providers:** AWS, GCP, Azure (API keys, tokens, passwords)
- **Developer Tools:** npm tokens, GitHub PATs, SSH keys
- **Cryptocurrency:** Wallet private keys
- **CI/CD:** GitHub Actions secrets, environment variables

**Sources:**
- [Trend Micro Technical Analysis](https://www.trendmicro.com/en_us/research/25/i/npm-supply-chain-attack.html)
- [Datadog Deep Dive](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Netskope Analysis](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)

### Exfiltration Technique

**Method:** GitHub repository creation + commit
**Stealth Factor:** HIGH - blends with normal developer activity, bypasses firewalls

**v3.0 Exfiltration Flow:**
1. Creates public GitHub repo using stolen PAT
2. Repo name: "Shai-Hulud" (v1/v2) or custom (v3)
3. **NEW:** Repo description: "Goldox-T3chs: Only Happy Girl"
4. Double Base64-encodes stolen secrets
5. Commits to JSON files: 3nvir0nm3nt.json, cl0vd.json, c9nt3nts.json
6. **Advantage:** HTTPS to api.github.com appears legitimate, evades network monitoring

**Sources:**
- [GitLab Discovery Report](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/)
- [Expel SOC Analysis](https://expel.com/blog/the-second-coming-of-shai-hulud/)

### Self-Propagation (Worm Behavior)

**Mechanism:**
1. Harvests victim's npm token
2. Queries npm API for victim's published packages
3. Selects up to **100 most-downloaded packages**
4. Injects malicious `preinstall` script + payloads
5. Publishes new compromised versions
6. Exponential spread without actor intervention

**Impact:** 132 million monthly downloads across 492 compromised packages (v2.0)

**Sources:**
- [ReversingLabs Worm Analysis](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
- [Sonatype Risk Assessment](https://www.sonatype.com/blog/ongoing-npm-software-supply-chain-attack-exposes-new-risks)

---

## Indicators of Compromise (IOCs)

### Shai Hulud 3.0 Specific IOCs

**Package:**
- `@vietmoney/react-big-calendar@0.26.2`

**File Names:**
- `bun_installer.js` (initial dropper)
- `environment_source.js` (obfuscated payload)
- `3nvir0nm3nt.json` (exfiltrated environment secrets)
- `cl0vd.json` (cloud provider credentials)
- `c9nt3nts.json` (additional stolen data)

**GitHub Repository Markers:**
- Description: **"Goldox-T3chs: Only Happy Girl"**
- Repository Name: May vary (no longer standardized "Shai-Hulud")
- Search String in Actions: **"SHA1HULUD"**

**Installation Artifacts:**
- `~/.truffler-cache/` (TruffleHog binary)
- Unexpected Bun runtime installations
- New `preinstall` scripts in package.json

### Shai Hulud 2.0 IOCs (For Context)

**Repository Markers:**
- Description: "Sha1-Hulud: The Second Coming"
- Repository Name: "shai-hulud"
- Workflow File: `.github/workflows/shai-hulud-workflow.yml`
- Branch Name: "shai-hulud"

**File Hashes:**
- `bun_environment.js`: `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- `setup_bun.js`: `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`

**Webhook URL:**
- `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`

**Sources:**
- [Upwind IOC List](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm)
- [Netskope Indicators](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)
- [GitHub IOC Scanner (agilesix)](https://github.com/agilesix/shai-hulud-response)
- [Wiz IOC Repository](https://github.com/wiz-sec-public/wiz-research-iocs/)

---

## Victimology Analysis

### Organizational Impact (All Campaigns)

**Total Organizations Compromised:** 1,195 (Entro analysis of 30,000+ repos)

**Sector Breakdown:**
- **Technology/SaaS:** 647 (54%)
- **Financial Services/Banking:** 53 (4%)
- **Healthcare:** 38 (3%)
- **Insurance:** 26 (2%)
- **Media:** 21 (2%)
- **Telecom:** 20 (2%)
- **Logistics:** 15 (1%)
- **Government:** Multiple (exact count not disclosed)
- **Other:** Education, manufacturing, real estate, aviation, retail

**Notable Victims:**
- **Tier-1 Organizations:** Major semiconductor company, digital asset custody provider
- **CrowdStrike** (v1.0 - ironic given they're a cybersecurity vendor)
- **Zapier** (automation platform)
- **ENS Domains** (Ethereum Name Service)
- **PostHog** (product analytics)
- **Postman** (API development)
- **AsyncAPI** (API specification - OpenVSX key stolen)
- **Browserbase**

### Financial Losses

**Trust Wallet Heist (v2.0):**
- **Amount:** $8.5 million in cryptocurrency
- **Wallets Affected:** 2,520
- **Attack Vector:** Private keys exfiltrated via Shai Hulud infection

**Total Estimated Losses (v1.0):**
- **Amount:** ~$50 million in cryptocurrency

**Sources:**
- [Entro Victimology Report](https://entro.security/blog/shai-hulud-2-0-banks-gov-tech-breach/)
- [CyberSecurity News](https://cybersecuritynews.com/shai-hulud-2-0/)
- [SecurityWeek Trust Wallet](https://www.securityweek.com/shai-hulud-supply-chain-attack-led-to-8-5-million-trust-wallet-heist/)
- [Aikido v2.0 Analysis](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)

### Compromised Packages Statistics

**v1.0:** 500+ packages, 1,150+ versions
**v2.0:** 796 packages, 20M+ weekly downloads
**v3.0:** 1 package (testing phase)

**High-Profile Packages (v1.0/v2.0):**
- `ngx-bootstrap` (300k weekly downloads)
- `ng2-file-upload` (100k weekly downloads)
- `@ctrl/tinycolor` (2.2M weekly downloads)
- `@ensdomains/solsha1`
- `@asyncapi/cli`

**Sources:**
- [Socket.dev Package Analysis](https://socket.dev/blog/shai-hulud-strikes-again-v2)
- [Snyk Package Tracking](https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/)

---

## Related CVEs (Contextual, Not Shai Hulud Specific)

### CVE-2025-10894 (Nx Supply Chain Attack)
**Date:** August 26, 2025
**CVSS:** 9.6 (Critical)
**Relevance:** Possibly linked to same actor, similar GitHub Actions workflow exploit

**Attack Vector:**
- Flawed GitHub Actions workflow (pull_request_target trigger)
- Unsanitized PR titles allowed code injection
- Malicious telemetry.js via post-install script

**Impact:**
- 400+ users/organizations
- 5,500+ private repos exposed publicly
- Harvested: GitHub tokens, npm tokens, SSH keys, crypto wallets

**Sources:**
- [ZeroPath Technical Analysis](https://zeropath.com/blog/cve-2025-10894-nx-npm-supply-chain-attack-summary)
- [Wiz CVE Database](https://www.wiz.io/vulnerability-database/cve/cve-2025-10894)
- [GitHub Advisory](https://github.com/advisories/GHSA-cxm3-wv7p-598c)

### CVE-2025-59037 (DuckDB npm Compromise)
**Date:** September 8, 2025
**CVSS:** 8.6 (High)
**Relevance:** Part of same September 2025 npm compromise wave

**Attack Vector:**
- Phishing email from spoofed npmjs.help domain
- Pixel-perfect npm website copy
- Maintainer tricked into 2FA reset

**Affected Packages:**
- `@duckdb/node-api@1.3.3`
- `@duckdb/node-bindings@1.3.3`
- `duckdb@1.3.3`
- `@duckdb/duckdb-wasm@1.29.2`

**Impact:**
- Cryptocurrency transaction interference
- **No confirmed downloads** (caught before widespread infection)

**Sources:**
- [GitLab Advisory](https://advisories.gitlab.com/pkg/npm/@duckdb/duckdb-wasm/CVE-2025-59037/)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-59037)
- [Aikido Report](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)

### CVE-2025-66478 → CVE-2025-55182 (React2Shell)
**Merged CVE:** CVE-2025-55182
**CVSS:** 10.0 (Critical)
**Relevance:** Concurrent npm ecosystem threat (not Shai Hulud, but similar timing)

**Attack:**
- Pre-authentication RCE in React Server Components, Next.js
- Exploitation detected December 5, 2025
- Coin miners deployed to Windows/Linux

**Sources:**
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/)

---

## Detection and Mitigation

### Immediate Actions (If Compromised)

1. **Remove Malicious Package:**
   ```bash
   npm uninstall @vietmoney/react-big-calendar
   rm -rf node_modules
   npm cache clean --force
   ```

2. **Rotate ALL Credentials:**
   - npm tokens (automation + publish)
   - GitHub Personal Access Tokens (PATs)
   - GitHub Actions secrets
   - SSH keys
   - AWS/GCP/Azure API keys
   - Cloud provider secrets (Secret Manager, Key Vault, Secrets Manager)
   - Cryptocurrency wallet keys

3. **Hunt for Exfiltration Repos:**
   - Search GitHub for repos with description: **"Goldox-T3chs: Only Happy Girl"**
   - Search for repos named "Shai-Hulud" or "shai-hulud"
   - Check for unexpected public repos created in affected timeframe

4. **Audit CI/CD Logs:**
   - Suspicious npm installs
   - Unauthorized package publishes
   - Anomalous GitHub Actions workflow activity

5. **Check for Artifacts:**
   - `~/.truffler-cache/` directory
   - Files: 3nvir0nm3nt.json, cl0vd.json, c9nt3nts.json
   - Unexpected Bun runtime installations

### Long-Term Defenses

**1. Disable Lifecycle Scripts:**
```bash
npm config set ignore-scripts true
```
- Blocks preinstall/postinstall hooks (primary infection vector)
- **Trade-off:** May break legitimate packages requiring build scripts

**2. Dependency Pinning:**
```bash
npm ci  # Use lockfiles strictly
```
- Roll back to pre-November 21, 2025 versions
- Use `package-lock.json` or `pnpm-lock.yaml`

**3. npm Trusted Publishing:**
- Migrate from token-based to OIDC-based publishing
- Eliminates token theft risk

**4. Enforce MFA:**
- Phishing-resistant MFA (WebAuthn/FIDO2) for all developer accounts
- Required for npm publishes and GitHub writes

**5. Package Aging/Vetting:**
- Block brand-new package versions (e.g., < 7 days old)
- Implement allowlists for lifecycle scripts

**6. Runtime Monitoring:**
- Alert on install-time network calls
- Monitor for unexpected subprocess creation (Bun downloads)
- Detect TruffleHog execution

**7. Supply Chain Security Tools:**
- Socket.dev (firewall for npm)
- Mondoo (lifecycle script auditing)
- Snyk/GitHub Dependabot (vulnerability scanning)

### Microsoft Defender Detections

Microsoft released detection signatures for Shai Hulud 2.0:
- Behavioral detection for malicious lifecycle scripts
- GitHub Actions workflow anomaly detection
- TruffleHog execution alerts

**Source:**
- [Microsoft Shai Hulud 2.0 Guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

### Community Detection Tools

**GitHub Repositories:**
- [agilesix/shai-hulud-response](https://github.com/agilesix/shai-hulud-response) - MDM-deployable IOC scanner (Mac/PC)
- [safedep/shai-hulud-migration-response](https://github.com/safedep/shai-hulud-migration-response) - Migration detection
- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) - Simple detection project

**IOC Feeds:**
- [Wiz Research IOCs](https://github.com/wiz-sec-public/wiz-research-iocs/)
- Cycode Threat Intel Feed (updated with IOCs)

---

## Industry Response

### Vendor Advisories

| Vendor | Report Date | URL |
|--------|-------------|-----|
| **Aikido** | Dec 29, 2025 | [Link](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path) |
| **Wiz** | Nov 24, 2025 | [Link](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack) |
| **Datadog** | Nov 2025 | [Link](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/) |
| **Socket** | Dec 23, 2025 | [Link](https://socket.dev/blog/shai-hulud-strikes-again-v2) |
| **Snyk** | Sep 2025, Dec 2025 | [Link](https://snyk.io/blog/shai-hulud-3-0/) |
| **Microsoft** | Dec 9, 2025 | [Link](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| **JFrog** | Nov 2025 | [Link](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/) |
| **GitLab** | Nov 2025 | [Link](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) |
| **Upwind** | Dec 2025 | [Link](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm) |
| **Mondoo** | Dec 2025 | [Link](https://mondoo.com/blog/shai-hulud-strikes-back-with-v3-0-the-evolution-of-a-potent-and-persistent-npm-supply-chain-worm) |

### Government Response

**CISA (US Cybersecurity and Infrastructure Security Agency):**
- Issued alert September 23, 2025
- Warnings for npm ecosystem supply chain compromise
- No KEV catalog entry (tracks CVEs, not malware campaigns)

**Source:**
- [CISA Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)

### npm/GitHub Response

**npm Security Measures (Dec 9, 2025):**
- Revoked all classic npm tokens
- Enforced session-based authentication
- CLI token management now required
- Pushed Trusted Publishing adoption

**GitHub Actions:**
- Disabled attacker-created repos ~8 hours after Nx compromise (CVE-2025-10894)
- Enhanced monitoring for bulk repository creation

**Sources:**
- [GitHub Changelog - Token Revocation](https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/)
- [GitHub Changelog - Auth Changes](https://github.blog/changelog/2025-09-29-strengthening-npm-security-important-changes-to-authentication-and-token-management/)

---

## Intelligence Gaps and Unknowns

### Unanswered Questions

1. **Attribution:**
   - Who is the threat actor? (No traditional IOCs - email, language, known infrastructure)
   - State-sponsored or financially motivated cybercrime?
   - Connection to August 2025 Nx compromise?

2. **Initial Access:**
   - How did actor compromise original maintainer accounts?
   - Phishing campaign (like DuckDB)? Credential stuffing? Session hijacking?

3. **Goldox-T3chs Significance:**
   - Why rebrand from "Shai-Hulud" to "Goldox-T3chs: Only Happy Girl"?
   - Is this a new group or operational security improvement?
   - "Only Happy Girl" - cultural reference or operational joke?

4. **hoquocdat Account:**
   - Was @vietmoney/react-big-calendar account compromised or malicious from origin?
   - Package dormant 2021-2025 - long-term sleeper or recent takeover?

5. **m.fasterxml.org:**
   - No evidence found of this being C2 infrastructure
   - Likely legitimate Maven metadata subdomain
   - Where did this indicator originate?

6. **Future Targets:**
   - Will actor expand to PyPI, RubyGems, crates.io?
   - v3.0 testing phase suggests v3.1 imminent?

---

## Analyst Assessment

### Threat Prognosis: HIGH and INCREASING

**Rationale:**
1. **Persistence:** 3 major waves over 4 months shows dedicated, resourced actor
2. **Evolution:** Each version addresses prior weaknesses (Windows support, obfuscation)
3. **Limited v3.0 Spread:** Testing phase indicates operational caution, not retreat
4. **Financial Success:** $58.5M+ stolen across campaigns funds continued operations
5. **Ecosystem Vulnerability:** npm's install-time scripts remain exploitable

**Predicted Timeline:**
- **Q1 2026:** Shai Hulud 3.1/4.0 launch expected
- **Potential Improvements:**
  - Multi-registry targeting (PyPI, RubyGems)
  - More sophisticated obfuscation (code virtualization)
  - Ransomware/extortion capabilities
  - Supply chain persistence (backdoors in legitimate package updates)

### Recommendations for Publication

**Key Findings Worthy of Public Disclosure:**

1. **"Goldox-T3chs: Only Happy Girl" Branding**
   - NEW indicator not widely reported
   - Critical for GitHub repository hunting

2. **Dead Man's Switch Removal**
   - Signals shift from destructive to stealthy operations
   - Indicates long-term campaign vs. smash-and-grab

3. **hoquocdat/@vietmoney Account Compromise**
   - Demonstrates 4+ year dormant package hijacking
   - Challenges "trust old packages" heuristic

4. **Trust Wallet $8.5M Heist Attribution**
   - Direct financial impact quantification
   - Links supply chain attack to cryptocurrency theft

5. **1,195 Organizations Victimology**
   - Sector breakdown shows no vertical is safe
   - Government/critical infrastructure impact underreported

6. **Windows Compatibility Fix**
   - Expands attack surface to non-Unix developers
   - Corporate Windows environments now at risk

---

## Conclusion

Shai Hulud 3.0 "The Golden Path" represents a **maturation, not conclusion**, of one of the most sophisticated npm supply chain campaigns in history. The limited spread of v3.0 suggests the threat actor is testing enhancements before a larger v3.1/v4.0 deployment, likely targeting Q1 2026.

The financial success of previous campaigns ($58.5M+ stolen), combined with technical evolution and persistent operations, indicates a well-resourced, patient adversary. Organizations must assume Shai Hulud will remain an active threat into 2026 and beyond.

**Critical Takeaway:** The removal of the dead man's switch and shift to "Goldox-T3chs" branding suggests the actor prioritizes **stealth and longevity over destruction**, making detection and attribution more challenging for defenders.

---

## Sources Summary

**Total Sources Consulted:** 75+ unique URLs across:
- Security vendor blogs (Aikido, Wiz, Datadog, Snyk, Socket, JFrog, etc.)
- Threat intelligence platforms (ReversingLabs, Netskope, Mondoo)
- Government advisories (CISA)
- Package registry responses (npm, GitHub)
- CVE databases (NVD, GitHub Advisory Database)
- Community detection tools (GitHub repositories)

**Primary Sources:**
1. [Aikido - Golden Path Discovery](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)
2. [Wiz - Shai Hulud 2.0 Analysis](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
3. [Entro - Victimology Report](https://entro.security/blog/shai-hulud-2-0-banks-gov-tech-breach/)
4. [Microsoft - Detection Guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
5. [Upwind - Technical Deep Dive](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm)

---

**Report Generated:** January 2, 2026
**Analyst:** RAPTOR OSS-Forensics Agent
**Classification:** UNCLASSIFIED // FOR PUBLIC RELEASE
