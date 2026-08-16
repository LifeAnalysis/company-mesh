import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const execFile = promisify(execFileCallback);
const [dataA, dataB, socketA, socketB] = process.argv.slice(2);
if (!dataA || !dataB || !socketA || !socketB) {
  throw new Error('Usage: node scripts/two-node-smoke.mjs DATA_A DATA_B SOCKET_A SOCKET_B');
}

async function connect(socket, agent) {
  const client = new Client({ name: `smoke-${agent}`, version: '0.1.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['packages/company-mcp/dist/index.js'],
    env: { ...process.env, COMPANY_MESH_SOCKET: socket, COMPANY_AGENT_ID: agent },
  });
  await client.connect(transport);
  return { client, transport };
}

async function call(client, name, args) {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError) throw new Error(`${name} failed: ${JSON.stringify(result.structuredContent)}`);
  return result.structuredContent;
}

const a = await connect(socketA, 'agent:builder');
const b = await connect(socketB, 'agent:friend');
const reviewer = await connect(socketA, 'agent:reviewer');

try {
  const inviteResult = await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'invite', 'create', '--invitee-label', 'node-b',
    '--scope', 'project:company-mesh', '--rate-per-minute', '30', '--expires-hours', '1',
  ]);
  const invite = inviteResult.stdout.trim();
  if (!invite) throw new Error('Invite creation returned no token.');
  await execFile('target/debug/company-mesh', ['--data-dir', dataB, 'join', invite]);
  let inviteReplayRejected = false;
  try {
    await execFile('target/debug/company-mesh', ['--data-dir', dataB, 'join', invite]);
  } catch {
    inviteReplayRejected = true;
  }
  if (!inviteReplayRejected) throw new Error('A used invite was accepted again.');

  const identityA = await call(a.client, 'mesh_get_identity', {});
  const identityB = await call(b.client, 'mesh_get_identity', {});

  const operationsPath = join(dataA, 'test-service-operations.json');
  await writeFile(operationsPath, JSON.stringify({
    inspect: {
      arguments: ['delegated-project', '{project}', '{environment}', '{limit}'],
      parameters: {
        environment: {
          type: 'string', allowed_values: ['preview', 'production'], max_length: 20,
        },
        limit: {
          type: 'integer', pattern: '^[1-9][0-9]?$', max_length: 2,
        },
      },
    },
  }), { mode: 0o600 });
  await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'delegation', 'register-service', '--name', 'test-cli',
    '--executable', '/bin/echo', '--operations-json', operationsPath,
  ]);
  const delegation = await call(b.client, 'mesh_request_service_access', {
    endpoint_addr: identityA.endpoint_addr, service: 'test-cli', project: 'company-mesh',
    operations: ['inspect'], reason: 'Verify project-scoped delegated execution.',
  });
  await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'delegation', 'approve', '--request-id', delegation.request_id,
    '--operation', 'inspect', '--expires-minutes', '5', '--max-calls', '1',
  ]);
  const grantsResponse = await call(b.client, 'mesh_list_service_grants', {});
  const grants = grantsResponse.result ?? grantsResponse.items ?? grantsResponse;
  const grant = grants.find(item => item.service === 'test-cli' && item.project === 'company-mesh');
  if (!grant) throw new Error('Delegated service grant was not stored by node B.');
  const invalidParameters = await b.client.callTool({
    name: 'mesh_call_service',
    arguments: {
      grant_id: grant.grant_id, operation: 'inspect',
      parameters: { environment: 'unknown', limit: 10 },
    },
  });
  if (!invalidParameters.isError) {
    throw new Error('A delegated value outside the registered allowlist was accepted.');
  }
  const delegatedResult = await call(b.client, 'mesh_call_service', {
    grant_id: grant.grant_id, operation: 'inspect',
    parameters: { environment: 'preview', limit: 10 },
  });
  if (!delegatedResult.success
    || !delegatedResult.stdout.includes('delegated-project company-mesh preview 10')) {
    throw new Error(`Delegated project-scoped service execution failed: ${JSON.stringify(delegatedResult)}`);
  }
  const exhausted = await b.client.callTool({
    name: 'mesh_call_service',
    arguments: {
      grant_id: grant.grant_id, operation: 'inspect',
      parameters: { environment: 'preview', limit: 10 },
    },
  });
  if (!exhausted.isError) throw new Error('Exhausted delegated grant was accepted.');

  const revocationRequest = await call(b.client, 'mesh_request_service_access', {
    endpoint_addr: identityA.endpoint_addr, service: 'test-cli', project: 'company-mesh',
    operations: ['inspect'], reason: 'Verify immediate grant revocation.',
  });
  const revocationApproval = await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'delegation', 'approve', '--request-id', revocationRequest.request_id,
    '--operation', 'inspect', '--expires-minutes', '5', '--max-calls', '2',
  ]);
  const revocableGrant = JSON.parse(revocationApproval.stdout);
  await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'delegation', 'revoke', '--grant-id', revocableGrant.grant_id,
  ]);
  const revoked = await b.client.callTool({
    name: 'mesh_call_service',
    arguments: {
      grant_id: revocableGrant.grant_id, operation: 'inspect',
      parameters: { environment: 'preview', limit: 10 },
    },
  });
  if (!revoked.isError) throw new Error('Revoked delegated grant was accepted.');
  await call(a.client, 'mesh_send_peer_message', {
    endpoint_addr: identityB.endpoint_addr,
    scope: 'project:company-mesh',
    message: 'Authenticated hello from node A to node B.',
  });
  const inbox = await call(b.client, 'mesh_list_inbox', { limit: 10 });
  const messages = inbox.result ?? inbox.items ?? inbox;
  if (!Array.isArray(messages) || !messages.some(item => item.payload?.text?.includes('Authenticated hello'))) {
    throw new Error('Node B did not receive the authenticated Iroh message.');
  }

  await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'peers', 'block', identityB.endpoint_id,
  ]);
  const blockedSend = await b.client.callTool({
    name: 'mesh_send_peer_message',
    arguments: {
      endpoint_addr: identityA.endpoint_addr,
      scope: 'project:company-mesh',
      message: 'This message must be blocked.',
    },
  });
  if (!blockedSend.isError) throw new Error('A blocked peer was still able to send.');
  await execFile('target/debug/company-mesh', [
    '--data-dir', dataA, 'peers', 'unblock', identityB.endpoint_id,
  ]);
  await call(b.client, 'mesh_send_peer_message', {
    endpoint_addr: identityA.endpoint_addr,
    scope: 'project:company-mesh',
    message: 'Message after explicit unblock.',
  });

  const suffix = Date.now().toString(36);
  const first = `T-${suffix}-1`;
  const second = `T-${suffix}-2`;
  await call(a.client, 'mesh_create_task', {
    task_id: first, title: 'Build the transport', project: 'company-mesh', depends_on: [], parallel_safe: false,
  });
  await call(a.client, 'mesh_create_task', {
    task_id: second, title: 'Use the transport', project: 'company-mesh', depends_on: [first], parallel_safe: true,
  });
  const initiallyReady = await call(a.client, 'mesh_list_ready_tasks', { project: 'company-mesh' });
  const firstReady = initiallyReady.result ?? initiallyReady.items ?? initiallyReady;
  if (!Array.isArray(firstReady) || !firstReady.some(task => task.task_id === first) || firstReady.some(task => task.task_id === second)) {
    throw new Error('Task dependency gate failed before task completion.');
  }
  await call(a.client, 'mesh_claim_task', { task_id: first });

  const selfReview = await a.client.callTool({
    name: 'mesh_record_review', arguments: { task_id: first, approved: true, artifact: 'review:self' },
  });
  if (!selfReview.isError) throw new Error('Self-review was accepted.');

  const review = await call(reviewer.client, 'mesh_record_review', {
    task_id: first, approved: true, artifact: 'review:independent',
  });
  await call(a.client, 'mesh_submit_task', {
    task_id: first, tests_passed: true, review_id: review.review_id, commit: 'abc123',
  });
  const finallyReady = await call(a.client, 'mesh_list_ready_tasks', { project: 'company-mesh' });
  const secondReady = finallyReady.result ?? finallyReady.items ?? finallyReady;
  if (!Array.isArray(secondReady) || !secondReady.some(task => task.task_id === second)) {
    throw new Error('Dependent task did not become ready.');
  }

  console.log(JSON.stringify({
    iroh_message: 'passed',
    signed_invite_enrollment: 'passed',
    single_use_invite: 'passed',
    block_and_unblock: 'passed',
    dependency_gate: 'passed',
    self_review_rejected: true,
    independent_review: 'passed',
    delegated_project_service: 'passed',
    delegated_parameter_validation: 'passed',
    delegated_grant_exhaustion: 'passed',
    delegated_grant_revocation: 'passed',
    next_ready_task: second,
  }, null, 2));
} finally {
  await Promise.all([a.transport.close(), b.transport.close(), reviewer.transport.close()]);
}
