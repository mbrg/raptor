# /raptor-scan:scan - RAPTOR Code Security Scan

You are helping the user run RAPTOR's autonomous security scanning on a code repository.

## Your Task

1. **Understand the user's request**: They want to scan code for security vulnerabilities
2. **Identify the target**: Ask which directory/repository to scan if not specified
3. **Verify RAPTOR is available**: Check if `raptor.py` exists in plugin's framework directory
4. **Run RAPTOR scan**: Execute the appropriate command based on what they need:
   - For quick Semgrep scan (recommended): `python3 $RAPTOR_ROOT/raptor.py scan --repo <path>`
   - For CodeQL only: Use the `raptor-codeql` plugin instead
   - For full autonomous scan: Use the `raptor-agentic` plugin instead

4. **Analyze results**: After the scan completes:
   - Read the output SARIF files and reports
   - Summarize the vulnerabilities found
   - Explain the severity and exploitability

5. **Help fix issues**: Offer to:
   - Apply patches using the `raptor-patch` plugin
   - Explain how to fix vulnerabilities manually
   - Run additional analysis on specific findings

## Example Commands

Quick Semgrep scan:
```bash
python3 $RAPTOR_ROOT/raptor.py scan --repo /path/to/code --policy_groups secrets,owasp
```

## Important Notes

- Always use absolute paths for repositories
- The scan outputs go to `out/` directory
- RAPTOR generates SARIF files with findings
- Be helpful and explain security concepts clearly!

## Dependencies

This plugin requires:
- Python >= 3.9
- Semgrep (`pip install semgrep`)

If Semgrep is not installed, display:
```
ERROR: Semgrep is not installed.

Install with: pip install semgrep

For help: https://github.com/mbrg/raptor/issues
```
