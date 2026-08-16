import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { daemonRpc } from './rpc.js';

test('daemonRpc returns typed results from the local socket', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'company-mcp-rpc-'));
  const socketPath = join(dir, 'test.sock');
  process.env.COMPANY_MESH_SOCKET = socketPath;
  const server = net.createServer(socket => {
    socket.once('data', data => {
      const request = JSON.parse(data.toString('utf8').trim()) as { id: string; method: string };
      socket.end(`${JSON.stringify({ id: request.id, ok: true, result: { method: request.method } })}\n`);
    });
  });
  await new Promise<void>((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  try {
    assert.deepEqual(await daemonRpc('health'), { method: 'health' });
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});

