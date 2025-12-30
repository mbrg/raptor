# /raptor-patch:patch - Generate Secure Patches (beta)

Generate secure patches to fix vulnerabilities.

## Prerequisites

Requires a SARIF file from a previous `/raptor-scan:scan` run.

## What It Does

- Analyzes findings with LLM
- Generates secure patch code
- Saves to `out/*/patches/`
- Does NOT generate exploits (use `/raptor-exploit:exploit` for that)

## Usage

```bash
python3 $RAPTOR_ROOT/raptor.py agentic --repo <path> --sarif <sarif-file> --no-exploits --max-findings <N>
```

## Example Workflow

```bash
/raptor-scan:scan test/              # First, find vulnerabilities
/raptor-patch:patch                  # Then, generate fixes for findings
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

## Important Notes

- Review patches before applying to production code
- Test patches in a development environment first
- Patches address the specific vulnerability pattern found
- Some patches may need manual adjustment for your codebase
