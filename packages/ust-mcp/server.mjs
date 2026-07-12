#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// ust-mcp stdio server — mounts the protocol tool registry over MCP (JSON-RPC on stdio). Run as `npx ust-mcp@rc`
// or wire into any MCP client. Transport is the only stateful part; the tools themselves are ust-protocol.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { listTools, dispatch } from './index.mjs';

const VERSION = '1.0.0-rc.7';
// Version handshake: report the resolved ust-protocol version too. A stale verifier gives confident WRONG
// verdicts, so WHICH protocol build is loaded is safety-relevant, not cosmetic. (ust-protocol doesn't export
// ./package.json, so resolve its entry and read the sibling manifest.)
let protoVersion = 'unknown';
try {
  const require = createRequire(import.meta.url);
  protoVersion = JSON.parse(readFileSync(join(dirname(require.resolve('ust-protocol')), 'package.json'), 'utf8')).version;
} catch { /* leave 'unknown' */ }

const server = new Server({ name: 'ust-mcp', version: VERSION }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: listTools() }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const r = await dispatch(req.params.name, req.params.arguments || {});
  return { content: [{ type: 'text', text: JSON.stringify(r.result ?? { error: r.error }, null, 2) }], isError: !!r.isError };
});
await server.connect(new StdioServerTransport());
console.error('ust-mcp ' + VERSION + ' (ust-protocol ' + protoVersion + ') — stdio server ready, ' + listTools().length + ' tools');

// Fire-and-forget update check → stderr notice (the claude-code pattern), dependency-free. Timeout-bounded,
// fail-silent, opt-out via NO_UPDATE_CHECK / CI. Makes staleness SELF-ANNOUNCING — the failure mode that just
// bit us (a stale server rejecting valid documents) is exactly what this surfaces.
if (!process.env.NO_UPDATE_CHECK && !process.env.CI) {
  fetch('https://registry.npmjs.org/-/package/ust-mcp/dist-tags', { signal: AbortSignal.timeout(2500) })
    .then((r) => r.json())
    .then((tags) => {
      const newest = Object.values(tags).sort(cmpVer).pop();
      if (newest && cmpVer(VERSION, newest) < 0) {
        const chan = tags.rc === newest ? 'rc' : 'latest';
        console.error('  ⚠ ust-mcp update available: ' + VERSION + ' → ' + newest + '  (run: npm i -g ust-mcp@' + chan + ')');
      }
    })
    .catch(() => { /* offline / registry down — never block the server */ });
}

// minimal semver comparator for 1.0.0-rc.N (a final release outranks any -rc of the same core).
function cmpVer(a, b) {
  const parse = (v) => { const [core, pre] = String(v).split('-'); return [...core.split('.').map(Number), pre ? Number(pre.replace(/\D/g, '')) : Infinity]; };
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] ?? 0) - (pb[i] ?? 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}
