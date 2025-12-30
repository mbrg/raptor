The original raptor.py still works. All requirements have been met:

  Summary

  The RAPTOR project has been transformed into a Claude Code plugin marketplace:

  What Was Created

  1. Marketplace Manifest (.claude-plugin/marketplace.json)
    - 10 plugins available for individual installation
    - Proper metadata, versioning, and keywords
  2. 10 Individual Plugins (in plugins/ directory)
    - raptor-scan - Static analysis with Semgrep
    - raptor-fuzz - Binary fuzzing with AFL++
    - raptor-web - Web application scanning
    - raptor-agentic - Full autonomous workflow
    - raptor-codeql - CodeQL analysis
    - raptor-analyze - LLM analysis on SARIF
    - raptor-crash-analysis - Crash root-cause analysis
    - raptor-oss-forensics - GitHub forensic investigation
    - raptor-exploit - Exploit PoC generation
    - raptor-patch - Secure patch generation
  3. Dependency Management
    - Each plugin has dependencies in manifest
    - raptor-deps-check.py validates all dependencies
    - Clear error messages when dependencies missing
  4. Safety Configuration
    - plugins/shared/safety-config.json - Sandbox and permission defaults
    - All plugins run sandboxed by default
    - Network and filesystem restrictions defined
  5. Error Handling
    - plugins/shared/error-messages.json - Comprehensive error catalog
    - Each error has code, message, solution, and support URL
  6. Documentation
    - plugins/README.md - Full installation and usage guide
    - plugins/settings-template.json - Settings for teams

  How Users Consume Plugins

  # Add marketplace
  /plugin marketplace add mbrg/raptor

  # Install individual plugins
  /plugin install raptor-scan@raptor-plugins
  /plugin install raptor-agentic@raptor-plugins

  # Use plugins
  /raptor-scan:scan ./my-project
  /raptor-agentic:agentic ./my-project

  Backward Compatibility

  Original commands in .claude/commands/ are preserved, so existing users can continue using:
  - /scan, /fuzz, /web
  - /agentic, /codeql, /analyze
  - /crash-analysis, /oss-forensics
  - /exploit, /patch

  COMPLETE
