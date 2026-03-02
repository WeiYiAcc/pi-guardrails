---
"@aliou/pi-guardrails": patch
---

Harden permission-gate command explanation prompt handling, fix dangerous-pattern matching flow after successful AST parses, and improve policy enforcement by skipping empty rules and resolving onlyIfExists checks relative to session cwd. Also refresh README/AGENTS docs for the policies-based architecture.