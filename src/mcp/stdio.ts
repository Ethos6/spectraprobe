/**
 * Dependency-free MCP server over stdio (JSON-RPC 2.0, protocol 2024-11-05).
 * One JSON message per line in, one per line out; logs go to stderr. Running
 * this module starts the server and serves requests until stdin closes.
 */
import { createInterface } from "node:readline";
import { VERSION } from "../version.js";
import { SpectraMcp } from "./server.js";

const PROTOCOL = "2024-11-05";

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
}

const engine = new SpectraMcp();

function send(message: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(message) + "\n");
}

async function handle(msg: JsonRpcMessage): Promise<Record<string, unknown> | null> {
  const { id, method } = msg;
  const params = msg.params ?? {};

  try {
    switch (method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: typeof params.protocolVersion === "string" ? params.protocolVersion : PROTOCOL,
            capabilities: { tools: {} },
            serverInfo: { name: "spectraprobe", version: VERSION },
          },
        };
      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: engine.listTools() } };
      case "tools/call": {
        const name = params.name as string;
        const args = (params.arguments as Record<string, unknown>) ?? {};
        try {
          const result = await engine.call(name, args);
          return {
            jsonrpc: "2.0",
            id,
            result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
          };
        } catch (e) {
          return {
            jsonrpc: "2.0",
            id,
            result: { content: [{ type: "text", text: `Error: ${(e as Error).message}` }], isError: true },
          };
        }
      }
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      default:
        if (id === undefined || id === null) return null; // notification
        return { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } };
    }
  } catch (e) {
    return { jsonrpc: "2.0", id: id ?? null, error: { code: -32603, message: (e as Error).message } };
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
process.stderr.write(`spectraprobe MCP server v${VERSION} ready (stdio)\n`);

// Requests are processed strictly in order: each completes before the next
// starts. This keeps session-dependent tools (search_evidence,
// get_analysis_status) consistent and bounds concurrent resource use.
let queue: Promise<void> = Promise.resolve();

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg: JsonRpcMessage;
  try {
    msg = JSON.parse(trimmed) as JsonRpcMessage;
  } catch {
    return; // ignore non-JSON lines
  }
  queue = queue.then(async () => {
    const reply = await handle(msg);
    if (reply !== null) send(reply);
  });
});

// On stdin close, finish queued requests before exiting so piped/batch
// invocations do not drop their final replies.
rl.on("close", () => {
  void queue.then(() => process.exit(0));
});
