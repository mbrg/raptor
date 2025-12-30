# RAPTOR Plugin Marketplace

RAPTOR Security Framework plugins for Claude Code. Install individual security tools or the entire framework.

## Quick Start

### Add the Marketplace

```bash
# Add RAPTOR marketplace to Claude Code
/plugin marketplace add mbrg/raptor
```

### Install Plugins

```bash
# Install individual plugins
/plugin install raptor-scan@raptor-plugins       # Code scanning
/plugin install raptor-fuzz@raptor-plugins       # Binary fuzzing
/plugin install raptor-web@raptor-plugins        # Web scanning
/plugin install raptor-agentic@raptor-plugins    # Full autonomous workflow

# Install all plugins
/plugin install raptor-scan@raptor-plugins raptor-fuzz@raptor-plugins raptor-web@raptor-plugins raptor-agentic@raptor-plugins raptor-codeql@raptor-plugins raptor-analyze@raptor-plugins raptor-crash-analysis@raptor-plugins raptor-oss-forensics@raptor-plugins raptor-exploit@raptor-plugins raptor-patch@raptor-plugins
```

### Use Plugins

After installation, use the namespaced commands:

```bash
/raptor-scan:scan ./my-project           # Scan code for vulnerabilities
/raptor-fuzz:fuzz ./my-binary            # Fuzz a binary for crashes
/raptor-web:web https://example.com      # Scan a web application
/raptor-agentic:agentic ./my-project     # Full autonomous analysis
```

## Available Plugins

| Plugin | Command | Description |
|--------|---------|-------------|
| `raptor-scan` | `/raptor-scan:scan` | Static analysis with Semgrep |
| `raptor-fuzz` | `/raptor-fuzz:fuzz` | Binary fuzzing with AFL++ |
| `raptor-web` | `/raptor-web:web` | OWASP Top 10 web scanning |
| `raptor-agentic` | `/raptor-agentic:agentic` | Full autonomous workflow |
| `raptor-codeql` | `/raptor-codeql:codeql` | Deep CodeQL analysis |
| `raptor-analyze` | `/raptor-analyze:analyze` | LLM analysis on SARIF |
| `raptor-crash-analysis` | `/raptor-crash-analysis:crash-analysis` | Crash root-cause analysis |
| `raptor-oss-forensics` | `/raptor-oss-forensics:oss-forensics` | GitHub forensic investigation |
| `raptor-exploit` | `/raptor-exploit:exploit` | Exploit PoC generation (beta) |
| `raptor-patch` | `/raptor-patch:patch` | Secure patch generation (beta) |

## Plugin Details

### raptor-scan
**Purpose**: Fast static analysis using Semgrep

**Dependencies**: Python 3.9+, Semgrep

**Install Semgrep**:
```bash
pip install semgrep
```

**Usage**:
```bash
/raptor-scan:scan /path/to/code
/raptor-scan:scan . --policy_groups secrets,owasp
```

---

### raptor-fuzz
**Purpose**: Binary fuzzing with AFL++ for crash discovery

**Dependencies**: Python 3.9+, AFL++

**Install AFL++**:
```bash
# macOS
brew install afl-fuzz

# Linux
apt install afl++
```

**Usage**:
```bash
/raptor-fuzz:fuzz /path/to/binary --duration 600
```

---

### raptor-web
**Purpose**: Web application security scanning

**Dependencies**: Python 3.9+, requests, beautifulsoup4

**Install**:
```bash
pip install requests beautifulsoup4
```

**Usage**:
```bash
/raptor-web:web https://example.com
```

---

### raptor-agentic
**Purpose**: Full autonomous workflow - scan, analyze, generate exploits and patches

**Dependencies**: Python 3.9+, Semgrep, LLM API key

**Setup**:
```bash
pip install semgrep
export ANTHROPIC_API_KEY=your_key  # or OPENAI_API_KEY
```

**Usage**:
```bash
/raptor-agentic:agentic /path/to/code
```

---

### raptor-codeql
**Purpose**: Deep semantic analysis with CodeQL

**Dependencies**: Python 3.9+, CodeQL CLI

**Install CodeQL**:
Download from: https://github.com/github/codeql-cli-binaries

**Usage**:
```bash
/raptor-codeql:codeql /path/to/code
```

---

### raptor-crash-analysis
**Purpose**: Autonomous root-cause analysis for C/C++ crashes

**Dependencies**: Python 3.9+, rr, gdb, gcov

**Install**:
```bash
# Linux only
sudo apt install rr gdb
```

**Usage**:
```bash
/raptor-crash-analysis:crash-analysis https://trac.ffmpeg.org/ticket/11234 https://github.com/FFmpeg/FFmpeg.git
```

---

### raptor-oss-forensics
**Purpose**: GitHub forensic investigation with GH Archive and Wayback Machine

**Dependencies**: Python 3.9+, Google Cloud credentials for BigQuery

**Setup**:
```bash
pip install google-cloud-bigquery google-auth pydantic requests
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

**Usage**:
```bash
/raptor-oss-forensics:oss-forensics "Investigate user X's activity on repo Y"
```

---

## Check Dependencies

Before using a plugin, verify dependencies are installed:

```bash
python3 plugins/raptor-deps-check.py raptor-scan
python3 plugins/raptor-deps-check.py --all
```

## Project-Level Installation

To share plugins with your team, add to your project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "raptor-plugins": {
      "source": {
        "source": "github",
        "repo": "mbrg/raptor"
      }
    }
  },
  "enabledPlugins": {
    "raptor-scan@raptor-plugins": true,
    "raptor-agentic@raptor-plugins": true
  }
}
```

Team members will be prompted to enable plugins when they open the project.

## Safety & Security

All RAPTOR plugins run in sandbox mode by default with these protections:

- **Sandboxed execution**: Bash commands run in restricted environment
- **Network restrictions**: Only allowed domains for forensics tools
- **File system isolation**: Limited to project directories and temp files
- **User approval**: Dangerous operations require explicit confirmation

See `plugins/shared/safety-config.json` for detailed security configuration.

## Error Handling

If you encounter errors, check `plugins/shared/error-messages.json` for solutions.

Common issues:

| Error | Solution |
|-------|----------|
| Semgrep not found | `pip install semgrep` |
| No LLM API key | `export ANTHROPIC_API_KEY=your_key` |
| AFL++ not found | `brew install afl-fuzz` (macOS) or `apt install afl++` (Linux) |
| GCP credentials missing | Set `GOOGLE_APPLICATION_CREDENTIALS` |

## Support

For help, report issues at: https://github.com/mbrg/raptor/issues

## License

Apache-2.0
