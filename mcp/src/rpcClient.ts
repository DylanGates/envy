// Client for the internal adapter<->core RPC spoken over
// <project>/.envy/mcp.sock (see cli/core/src/rpc.rs). This is envy's own
// internal wire format (JSON-RPC 2.0, newline-delimited) — not the
// public Model Context Protocol the agent speaks to this adapter.

import * as net from "node:net";
import * as path from "node:path";

interface RpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string };
}

const CONNECT_RETRY_ATTEMPTS = 20;
const CONNECT_RETRY_DELAY_MS = 100;

let nextId = 1;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableConnectError(err: NodeJS.ErrnoException): boolean {
  return err.code === "ECONNREFUSED" || err.code === "ENOENT";
}

async function connectWithRetry(
  socketPath: string,
  recentOutput: () => string[],
): Promise<net.Socket> {
  let lastError: NodeJS.ErrnoException | undefined;
  for (let attempt = 0; attempt < CONNECT_RETRY_ATTEMPTS; attempt++) {
    try {
      return await new Promise<net.Socket>((resolve, reject) => {
        const socket = net.createConnection({ path: socketPath });
        socket.once("connect", () => resolve(socket));
        socket.once("error", reject);
      });
    } catch (err) {
      lastError = err as NodeJS.ErrnoException;
      if (!isRetryableConnectError(lastError)) {
        throw lastError;
      }
      await sleep(CONNECT_RETRY_DELAY_MS);
    }
  }
  const output = recentOutput().join("\n");
  throw new Error(
    `could not connect to envy core at ${socketPath} after ${CONNECT_RETRY_ATTEMPTS} attempts` +
      (lastError ? `: ${lastError.message}` : "") +
      (output ? `\nRecent envy-core output:\n${output}` : ""),
  );
}

export async function callCore(
  projectRoot: string,
  method: string,
  params: unknown = {},
  recentOutput: () => string[] = () => [],
): Promise<unknown> {
  const socketPath = path.join(projectRoot, ".envy", "mcp.sock");
  const socket = await connectWithRetry(socketPath, recentOutput);

  return new Promise((resolve, reject) => {
    const id = nextId++;
    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex === -1) return;

      const line = buffer.slice(0, newlineIndex);
      socket.end();

      let response: RpcResponse;
      try {
        response = JSON.parse(line) as RpcResponse;
      } catch (err) {
        reject(new Error(`invalid response from envy core: ${(err as Error).message}`));
        return;
      }

      if (response.error) {
        reject(new Error(`envy core: ${response.error.message}`));
      } else {
        resolve(response.result);
      }
    });

    socket.on("error", (err) => reject(err));

    socket.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
