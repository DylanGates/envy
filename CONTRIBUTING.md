# Contributing to envy

Thank you for your interest in contributing to **envy**!

## Core Engineering & Security Principles

1. **The Inviolable Trust Boundary:**
   - The Rust core (`envy-core`) is the **only** component allowed to touch plaintext secrets.
   - The TypeScript adapter (`mcp/`) is untrusted and stateless. It must **never** store, inspect, or forward raw secret values.
2. **Zero Secret Leaks:**
   - Secrets must never be formatted into logs, stderr/stdout, temporary files, error messages, shell command arguments, or child process environment variables.
3. **No Unconsented Network Calls:**
   - Envy never makes speculative network requests or guesses endpoints. All provider egress must be approved via Provider Descriptors or explicit command-line flags.

---

## Development Setup

### Running Tests
```bash
# Run unit and integration tests (uses in-memory test doubles)
cargo test

# Run live keychain diagnostic tests (touches real OS keychain)
cargo test -- --ignored
```

### Formatting & Linting
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
pnpm --dir mcp run build
```

---

## Code Contribution Workflow

1. Fork the repository and create your feature branch: `git checkout -b feature/my-feature`.
2. Commit changes in logical, atomic increments.
3. Ensure all tests pass before submitting a Pull Request.
4. Follow conventional naming standards defined in `docs/ontology.md`.
