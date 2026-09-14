// envy's MCP adapter: the untrusted, stateless bridge between an AI
// agent (speaking the public Model Context Protocol, via
// @modelcontextprotocol/sdk over stdio) and the trusted Rust core
// (spoken to via the internal RPC in rpcClient.ts, over a local socket
// that this process spawns `envy mcp serve` to provide).
//
// This process must never store secrets or receive raw credential
// values — it only relays capability requests and their results.
//
// IMPORTANT: stdout is reserved for StdioServerTransport's JSON-RPC
// framing to the agent for this process's entire lifetime. All of this
// module's own diagnostics go to stderr (console.error) — never
// console.log/stdout.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { startCoreProcess } from "./coreProcess.js";
import { callCore } from "./rpcClient.js";

async function main(): Promise<void> {
  const projectRoot = process.argv[2] ?? process.cwd();
  const core = startCoreProcess(projectRoot);

  const server = new McpServer({ name: "envy", version: "0.1.0" });

  server.registerTool(
    "list_capabilities",
    {
      description: "Lists the envy capabilities this adapter can currently invoke.",
      inputSchema: {},
    },
    async () => {
      try {
        const result = await callCore(projectRoot, "list_capabilities", {}, core.recentOutput);
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: (err as Error).message }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "make_authenticated_request",
    {
      description:
        "Makes an authenticated GET request to a provider (e.g. context7) using a credential " +
        "stored in envy's vault. The credential value is never returned to the caller. " +
        "Non-GET methods currently fail closed (no consent flow exists yet).",
      inputSchema: {
        provider: z.string().describe("Provider id, e.g. \"context7\", \"stripe\"."),
        secretName: z.string().describe("Name of the vault secret to use, e.g. from `envy add`."),
        method: z.string().describe("HTTP method. Only GET is currently allowed."),
        path: z.string().describe("Path relative to the provider's base URL, e.g. \"/libs/search\"."),
        query: z
          .record(z.string(), z.string())
          .optional()
          .describe("Query string parameters."),
      },
    },
    async ({ provider, secretName, method, path, query }) => {
      try {
        const result = await callCore(
          projectRoot,
          "make_authenticated_request",
          { provider, secretName, method, path, query: query ?? {} },
          core.recentOutput,
        );
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: (err as Error).message }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "check_credential",
    {
      description:
        "Ad-hoc credential check: makes a read-only GET to a URL you supply, using a credential " +
        "stored in envy's vault, and reports whether it looks valid, invalid, or unknown. " +
        "The credential value is never returned. No provider catalog is used — the url you pass " +
        "is your explicit approval for this one call; envy never guesses or probes endpoints on " +
        "its own.",
      inputSchema: {
        secretName: z.string().describe("Name of the vault secret to check, e.g. from `envy add`."),
        url: z.string().describe("The HTTPS URL to call, e.g. \"https://api.example.com/me\"."),
        authStyle: z
          .enum(["bearer", "header"])
          .describe("How to inject the credential: \"bearer\" (Authorization: Bearer <value>) or \"header\"."),
        headerName: z
          .string()
          .optional()
          .describe("Header name to use when authStyle is \"header\"."),
      },
    },
    async ({ secretName, url, authStyle, headerName }) => {
      try {
        const result = await callCore(
          projectRoot,
          "check_credential",
          { secretName, url, authStyle, headerName },
          core.recentOutput,
        );
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: (err as Error).message }],
          isError: true,
        };
      }
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("envy-mcp: fatal error:", err);
  process.exit(1);
});
