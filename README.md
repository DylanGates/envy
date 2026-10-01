# envy

> **Your credentials are yours, not your agent's.**

**envy** is an open-source, local-first secrets manager and credential gateway designed for developers and AI coding agents (Claude Code, Cursor, Codex, etc.).

It discovers credentials across project files, identifies their service providers, stores secret values in an encrypted local vault protected by the OS keychain, and brokers capability requests so autonomous tools and AI agents can validate or use credentials without ever receiving raw secret plaintext.

---

## Features

- 🔒 **Local-First & Zero-Knowledge:** Works completely offline with zero cloud dependency. Plaintext values never touch disk unencrypted.
- 🛡️ **Trusted Core Security Boundary:** Plaintext secrets exist only inside the trusted Rust core (`envy-core`) and never leak into logs, shell arguments, subprocess environment variables, or MCP adapter memory.
- 🔑 **OS Keychain Key Protection:** Master data keys are protected using platform keychains (macOS Keychain, Linux Secret Service, Windows Credential Manager).
- 📦 **Encrypted Whole-Vault Backup:** Password-derived backups via **Argon2id** and **AES-256-GCM** authenticated envelopes.
- 🤖 **Agent Capability Gateway:** Built-in Model Context Protocol (MCP) server providing capability tools (`check_credential`, `make_authenticated_request`, `list_capabilities`) with strict domain allowlists and TTL-based human consent gating.
- 🔎 **Deep Secret Scanner:** Multi-format scanner extracting candidates from `.env`, JSON, TOML, YAML, Dockerfile, and source files using Shannon entropy scoring and provider pattern matching.
- 🧼 **Automatic Response Redaction:** Outbound provider payloads are sanitized to prevent accidental secret leakage in echoed responses.

---

## Installation & Build

### Prerequisites
- **Rust:** 1.80+ (`cargo`)
- **Node.js & pnpm:** Node 20+, `pnpm` 9+

### Build from Source
```bash
# Clone the repository
git clone https://github.com/DylanGates/envy.git
cd envy/cli

# Build the Rust CLI & Core library
cargo build --release

# Build the TypeScript MCP Adapter
pnpm --dir mcp install
pnpm --dir mcp run build
```

---

## CLI Usage

### 1. Initialize Vault
```bash
envy init
```

### 2. Scan Project for Credentials
```bash
envy scan
```

### 3. Add & Manage Secrets
```bash
# Add a secret securely
envy add STRIPE_API_KEY

# List stored secret metadata (never prints values)
envy list
```

### 4. Health Check Stored Credentials
```bash
# Check validity against a cataloged provider
envy check STRIPE_API_KEY --provider stripe

# Check against an ad-hoc HTTPS endpoint
envy check MY_API_KEY --url https://api.example.com/health --auth-style bearer
```

### 5. Encrypted Backup & Restore
```bash
# Export encrypted backup (Argon2id + AES-256-GCM)
envy export --encrypted vault.backup.enc

# Restore encrypted backup into a new vault
envy import --encrypted vault.backup.enc
```

### 6. Connect to AI Agents (Claude / Cursor)
```bash
# Expose Envy to your active Claude Code or Cursor installation
envy expose install claude-code
```

---

## Architecture & Trust Model

```
+-------------------------------------------------------------+
| AI Coding Agent (Claude, Cursor, Codex)                     |
+------------------------------+------------------------------+
                               | Model Context Protocol (MCP)
+------------------------------v------------------------------+
| TypeScript MCP Adapter (Stateless, Zero-Secret Memory)      |
+------------------------------+------------------------------+
                               | Local IPC Socket (0600)
====================== TRUST BOUNDARY =========================
+------------------------------v------------------------------+
| Trusted Rust Core (`envy-core`)                             |
|  - AES-256-GCM Authenticated Encryption                     |
|  - HKDF Subkey Separation (Encryption & Fingerprint)        |
|  - Domain Allowlist & Response Sanitization                 |
|  - OS Keychain Key Storage                                  |
+-------------------------------------------------------------+
```

---

## License

Licensed under the Apache License, Version 2.0 or MIT license at your option.
