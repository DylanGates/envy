// Spawns and manages the `envy mcp serve` child process (the trusted
// Rust core's local IPC server). This adapter is untrusted and stateless:
// it only ever talks to the core over the socket that process binds —
// see rpcClient.ts.
//
// IMPORTANT: this process's own stdout is reserved for the
// StdioServerTransport's JSON-RPC framing to the agent for its entire
// lifetime. The child's stdout/stderr must never be forwarded there —
// everything from the child, and all of this module's own diagnostics,
// goes to *our* stderr only.

import { type ChildProcessByStdio, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import * as path from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

const RING_BUFFER_LINES = 20;

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

export function resolveEnvyBinary(): string {
  // moduleDir is cli/mcp/dist when compiled; the Cargo build output for
  // the cli crate lives at cli/target/{debug,release}/envy.
  const candidates = [
    path.join(moduleDir, "..", "..", "target", "debug", "envy"),
    path.join(moduleDir, "..", "..", "target", "release", "envy"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  // Last resort: assume `envy` is on PATH. We can't verify this without
  // actually trying to spawn it, so just return the bare name and let
  // spawn() surface ENOENT if it isn't found either.
  return "envy";
}

export interface CoreProcessHandle {
  readonly child: ChildProcessByStdio<null, Readable, Readable>;
  /** Recent lines from the child's stdout/stderr, for diagnosing a
   * connection failure (e.g. surfacing a VaultNotFound message). */
  recentOutput(): string[];
}

export function startCoreProcess(projectRoot: string): CoreProcessHandle {
  const binary = resolveEnvyBinary();
  const child = spawn(binary, ["mcp", "serve", "--quiet"], {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const ring: string[] = [];
  const capture = (source: "stdout" | "stderr") => (chunk: Buffer) => {
    for (const line of chunk.toString("utf8").split("\n")) {
      if (line.length === 0) continue;
      ring.push(line);
      if (ring.length > RING_BUFFER_LINES) ring.shift();
      console.error(`[envy-core:${source}] ${line}`);
    }
  };
  child.stdout.on("data", capture("stdout"));
  child.stderr.on("data", capture("stderr"));

  child.on("exit", (code, signal) => {
    console.error(`[envy-core] process exited (code=${code}, signal=${signal})`);
  });
  child.on("error", (err) => {
    console.error(`[envy-core] failed to start ('${binary}'): ${err.message}`);
  });

  const shutdown = () => {
    if (!child.killed) {
      child.kill();
    }
  };
  process.on("exit", shutdown);
  process.on("SIGINT", () => {
    shutdown();
    process.exit();
  });
  process.on("SIGTERM", () => {
    shutdown();
    process.exit();
  });

  return {
    child,
    recentOutput: () => [...ring],
  };
}
