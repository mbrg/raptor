# /raptor-agentic:agentic - RAPTOR Full Autonomous Workflow

This is RAPTOR's most powerful mode - full autonomous security analysis.

## What This Does

1. Scan code with Semgrep/CodeQL
2. Analyze each finding with LLM
3. **Generate exploit PoCs** (proof-of-concept code)
4. **Generate secure patches**

Nothing will be applied to your code - only generated in `out/` directory.

## Your Task

1. **Identify the target**: Get the repository/directory path to scan
2. **Run RAPTOR in agentic mode**:
   ```bash
   python3 $RAPTOR_ROOT/raptor.py agentic --repo <path>
   ```

3. **Monitor progress**: The scan will:
   - Run Semgrep for quick vulnerability detection
   - Optionally run CodeQL for deeper analysis
   - Send findings to LLM for analysis
   - Generate exploits and patches

4. **Present results**: After completion:
   - Summarize vulnerabilities by severity
   - Show exploit PoCs generated
   - Show patches generated
   - Offer to apply patches or explain findings

## Example Commands

Full autonomous workflow:
```bash
python3 $RAPTOR_ROOT/raptor.py agentic --repo /path/to/code --max-findings 10
```

With specific options:
```bash
python3 $RAPTOR_ROOT/raptor.py agentic --repo /path/to/code --no-codeql --max-findings 5
```

## Dependencies

This plugin requires:
- Python >= 3.9
- Semgrep (`pip install semgrep`)
- LLM API key: Either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` must be set

If LLM API key is missing, display:
```
ERROR: No LLM API key found.

Set one of these environment variables:
  export ANTHROPIC_API_KEY=your_key
  export OPENAI_API_KEY=your_key

For help: https://github.com/mbrg/raptor/issues
```

## Important Notes

- This is the most comprehensive scan mode
- Results go to `out/` directory
- Generated exploits are for educational/research purposes only
- Review patches before applying to production code
