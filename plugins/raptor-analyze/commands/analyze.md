# /raptor-analyze:analyze - RAPTOR LLM Analysis

Analyzes existing SARIF files with LLM (for findings from previous scans).

## Your Task

1. **Identify inputs**:
   - Repository path (for context)
   - SARIF file from previous scan

2. **Run LLM analysis**:
   ```bash
   python3 $RAPTOR_ROOT/raptor.py analyze --repo <path> --sarif <sarif-file>
   ```

3. **Present results**: After completion:
   - Detailed analysis of each finding
   - Exploitability assessment
   - Suggested fixes

## Example Commands

Analyze existing SARIF:
```bash
python3 $RAPTOR_ROOT/raptor.py analyze --repo /path/to/code --sarif findings.sarif
```

## Dependencies

This plugin requires:
- Python >= 3.9
- LLM API key: Either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` must be set

If LLM API key is missing, display:
```
ERROR: No LLM API key found.

Set one of these environment variables:
  export ANTHROPIC_API_KEY=your_key
  export OPENAI_API_KEY=your_key

For help: https://github.com/mbrg/raptor/issues
```

## Use Cases

- Re-analyze findings with updated LLM
- Analyze SARIF from external tools (other scanners)
- Get detailed explanations for existing findings
