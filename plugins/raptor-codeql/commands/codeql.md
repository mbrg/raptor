# /raptor-codeql:codeql - RAPTOR CodeQL Analysis

Runs CodeQL-only deep static analysis with dataflow validation.

## Your Task

1. **Identify the target**: Get the repository path to analyze
2. **Run CodeQL analysis**:
   ```bash
   python3 $RAPTOR_ROOT/raptor.py codeql --repo <path>
   ```

3. **Present results**: After completion:
   - Summarize vulnerabilities found
   - Show dataflow paths for each finding
   - Explain the security implications

## What CodeQL Provides

- Deep semantic analysis (understands code flow)
- Dataflow tracking (source to sink)
- Taint analysis
- Complex vulnerability patterns that Semgrep misses

## Example Commands

Basic CodeQL scan:
```bash
python3 $RAPTOR_ROOT/raptor.py codeql --repo /path/to/code
```

## Dependencies

This plugin requires:
- Python >= 3.9
- CodeQL CLI (install from https://github.com/github/codeql-cli-binaries)

If CodeQL is not installed, display:
```
ERROR: CodeQL CLI is not installed or not in PATH.

Install from: https://github.com/github/codeql-cli-binaries
Follow setup guide: https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/

For help: https://github.com/mbrg/raptor/issues
```

## Important Notes

- CodeQL is slower but finds complex vulnerabilities
- Requires building a CodeQL database (automatic)
- Results are saved in SARIF format
- Database creation can take 10-30 minutes for large codebases
