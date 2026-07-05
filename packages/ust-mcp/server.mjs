#!/usr/bin/env node
// ust-mcp stdio server — mounts the protocol tool registry over MCP (JSON-RPC on stdio). Run as `npx ust-mcp`
// or wire into any MCP client. Transport is the only stateful part; the tools themselves are ust-protocol.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { listTools, dispatch } from './index.mjs';

const server = new Server({ name: 'ust-mcp', version: '1.0.0-rc.4' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: listTools() }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const r = dispatch(req.params.name, req.params.arguments || {});
  return { content: [{ type: 'text', text: JSON.stringify(r.result ?? { error: r.error }, null, 2) }], isError: !!r.isError };
});
await server.connect(new StdioServerTransport());
console.error('ust-mcp stdio server ready — ' + listTools().length + ' tools');
