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
  const isWindows = process.platform === "win32";
  const exeName = isWindows ? "envy.exe" : "envy";
  const candidates = [
    path.join(moduleDir, "..", "..", "target", "debug", exeName),
    path.join(moduleDir, "..", "..", "target", "release", exeName),
    path.join(moduleDir, "..", "..", "bin", exeName),
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

const MAX_RESTARTS = 5;
const BASE_RESTART_DELAY_MS = 500;
// After this many milliseconds of uptime without an exit, the restart
// counter resets so a temporarily-flaky core doesn't permanently exhaust
// the restart budget.
const UPTIME_RESET_MS = 30_000;

export interface CoreProcessHandle {
  /** Recent lines from the child's stdout/stderr, for diagnosing a
   * connection failure (e.g. surfacing a VaultNotFound message). */
  recentOutput(): string[];
}

export function startCoreProcess(projectRoot: string): CoreProcessHandle {
  const ring: string[] = [];
  let currentChild: ChildProcessByStdio<null, Readable, Readable> | null = null;
  let restarts = 0;
  let shutdownRequested = false;

  function launch(): void {
    if (shutdownRequested) return;

    const binary = resolveEnvyBinary();
    const child = spawn(binary, ["mcp", "serve", "--quiet"], {
      cwd: projectRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    currentChild = child;

    const capture = (source: string) => (chunk: Buffer) => {
      for (const line of chunk.toString("utf8").split("\n")) {
        if (line.length === 0) continue;
        ring.push(line);
        if (ring.length > RING_BUFFER_LINES) ring.shift();
        console.error(`[envy-core:${source}] ${line}`);
      }
    };
    child.stdout.on("data", capture("stdout"));
    child.stderr.on("data", capture("stderr"));

    child.on("error", (err) => {
      console.error(`[envy-core] failed to start ('${binary}'): ${err.message}`);
    });

    // Reset restart counter after stable uptime so a transient crash
    // doesn't permanently exhaust the budget.
    const uptimeTimer = setTimeout(() => {
      if (restarts > 0) {
        console.error("[envy-core] process stable, resetting restart counter");
        restarts = 0;
      }
    }, UPTIME_RESET_MS);
    // Don't hold the process open just for this timer.
    uptimeTimer.unref();

    child.on("exit", (code, signal) => {
      clearTimeout(uptimeTimer);
      if (shutdownRequested) return;
      console.error(`[envy-core] exited (code=${code}, signal=${signal})`);
      if (restarts < MAX_RESTARTS) {
        const delay = Math.min(BASE_RESTART_DELAY_MS * 2 ** restarts, 30_000);
        restarts++;
        console.error(
          `[envy-core] restarting in ${delay}ms (attempt ${restarts}/${MAX_RESTARTS})`,
        );
        setTimeout(launch, delay).unref();
      } else {
        console.error(
          "[envy-core] core process exited too many times — " +
            "restart budget exhausted; MCP tool calls will fail until " +
            "this adapter process is restarted.",
        );
      }
    });
  }

  // Register shutdown handlers once, outside the launch loop, so they
  // don't accumulate across restarts.
  const shutdown = (): void => {
    shutdownRequested = true;
    currentChild?.kill();
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

  launch();

  return {
    recentOutput: () => [...ring],
  };
}
