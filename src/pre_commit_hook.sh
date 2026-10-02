#!/usr/bin/env bash
# envy-pre-commit: Blocks committing plaintext credentials in staged files
# Installed via `envy git hook install`

set -e

if ! command -v envy &> /dev/null; then
    echo "⚠️  envy CLI not found on PATH. Skipping credential pre-commit check."
    exit 0
fi

# Run envy scan on the git staged index / working tree
SCAN_OUTPUT=$(envy scan . --json 2>/dev/null || true)

if echo "$SCAN_OUTPUT" | grep -q '"findings":\s*\[[^]]'; then
    echo ""
    echo "❌ [envy] PRE-COMMIT BLOCKED: Plaintext credential(s) detected in repository!"
    echo "-------------------------------------------------------------------------------"
    echo "$SCAN_OUTPUT" | grep -o '"var_name":"[^"]*"' | tr -d '"' | sed 's/var_name:/  • Plaintext variable: /'
    echo ""
    echo "👉 Run 'envy scan --remediate' to replace secrets with safe envy:// references."
    echo "👉 Or run 'envy import --env .env' and add '.env' to your .gitignore."
    echo "-------------------------------------------------------------------------------"
    exit 1
fi

exit 0
