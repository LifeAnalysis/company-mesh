import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const socket = process.env.COMPANY_MESH_SOCKET;
if (!socket) throw new Error('COMPANY_MESH_SOCKET is required');

const client = new Client({ name: 'company-permission-smoke', version: '0.1.0' });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ['packages/company-mcp/dist/index.js'],
  env: {
    ...process.env,
    COMPANY_MESH_SOCKET: socket,
    COMPANY_AGENT_ID: 'agent:observer',
    COMPANY_PERMISSION_PROFILE: 'observer',
  },
});
await client.connect(transport);
try {
  const listed = await client.listTools();
  const names = listed.tools.map(tool => tool.name);
  const forbidden = ['mesh_create_task', 'mesh_claim_task', 'mesh_submit_task',
    'mesh_record_review', 'mesh_propose_memory', 'mesh_send_peer_message'];
  if (forbidden.some(name => names.includes(name))) {
    throw new Error(`Observer profile exposed a write tool: ${JSON.stringify(names)}`);
  }
  if (names.length !== 7) throw new Error(`Expected 7 observer tools, got ${names.length}`);
  console.log(JSON.stringify({ observer_tools: names, write_tools_hidden: true }, null, 2));
} finally {
  await transport.close();
}
