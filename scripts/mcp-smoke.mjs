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
const tools = new Map(listed.tools.map(tool => [tool.name, tool]));
for (const name of ['mesh_get_identity', 'mesh_list_ready_tasks', 'mesh_search_memory',
  'mesh_list_peers', 'mesh_list_inbox', 'mesh_list_audit_events', 'mesh_verify_audit_chain']) {
  if (tools.get(name)?.annotations?.readOnlyHint !== true) {
    throw new Error(`${name} must be marked read-only`);
  }
}
if (tools.get('mesh_call_service')?.annotations?.destructiveHint !== true
  || tools.get('mesh_call_service')?.annotations?.openWorldHint !== true) {
  throw new Error('mesh_call_service must disclose destructive external effects');
}
const identity = await client.callTool({ name: 'mesh_get_identity', arguments: {} });
if (identity.isError || !identity.structuredContent) throw new Error('mesh_get_identity failed');
const memory = await client.callTool({
  name: 'mesh_propose_memory',
  arguments: {
    scope: 'project:company-mesh', kind: 'observation',
    content: 'The MCP smoke test reached companyd.', source_uri: 'test:mcp-smoke',
  },
});
if (memory.isError) throw new Error('mesh_propose_memory failed');
const search = await client.callTool({
  name: 'mesh_search_memory',
  arguments: { scope: 'project:company-mesh', query: 'smoke test', limit: 5 },
});
if (search.isError) throw new Error('mesh_search_memory failed');
const audit = await client.callTool({ name: 'mesh_verify_audit_chain', arguments: {} });
if (audit.isError || audit.structuredContent?.valid !== true) throw new Error('mesh_verify_audit_chain failed');
console.log(JSON.stringify({
  tools: listed.tools.map(tool => ({ name: tool.name, title: tool.title, annotations: tool.annotations })),
  identity: identity.structuredContent,
  memory: memory.structuredContent,
  search: search.structuredContent,
  audit: audit.structuredContent,
}, null, 2));
await transport.close();
