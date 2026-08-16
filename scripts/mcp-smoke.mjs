import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const socket = process.env.COMPANY_MESH_SOCKET;
if (!socket) throw new Error('COMPANY_MESH_SOCKET is required');

const client = new Client({ name: 'company-mesh-smoke', version: '0.1.0' });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ['packages/company-mcp/dist/index.js'],
  env: { ...process.env, COMPANY_MESH_SOCKET: socket, COMPANY_AGENT_ID: 'agent:smoke' },
});
await client.connect(transport);
const listed = await client.listTools();
if (listed.tools.length !== 16) throw new Error(`Expected 16 tools, got ${listed.tools.length}`);
const identity = await client.callTool({ name: 'company_identity', arguments: {} });
if (identity.isError || !identity.structuredContent) throw new Error('company_identity failed');
const memory = await client.callTool({
  name: 'company_memory_propose',
  arguments: {
    scope: 'project:company-mesh', kind: 'observation',
    content: 'The MCP smoke test reached companyd.', source_uri: 'test:mcp-smoke',
  },
});
if (memory.isError) throw new Error('company_memory_propose failed');
const search = await client.callTool({
  name: 'company_memory_search',
  arguments: { scope: 'project:company-mesh', query: 'smoke test', limit: 5 },
});
if (search.isError) throw new Error('company_memory_search failed');
const audit = await client.callTool({ name: 'company_audit_verify', arguments: {} });
if (audit.isError || audit.structuredContent?.valid !== true) throw new Error('company_audit_verify failed');
console.log(JSON.stringify({
  tools: listed.tools.map(tool => tool.name),
  identity: identity.structuredContent,
  memory: memory.structuredContent,
  search: search.structuredContent,
  audit: audit.structuredContent,
}, null, 2));
await transport.close();
