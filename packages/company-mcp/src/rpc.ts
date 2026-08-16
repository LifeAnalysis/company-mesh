import net from 'node:net';
import { randomUUID } from 'node:crypto';

export interface RpcErrorBody {
  code: string;
  message: string;
  retryable: boolean;
}

interface RpcResponse {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: RpcErrorBody;
}

export class RpcFailure extends Error {
  constructor(public readonly detail: RpcErrorBody) {
    super(detail.message);
    this.name = 'RpcFailure';
  }
}

export function daemonRpc<T>(method: string, params: unknown = {}): Promise<T> {
  const socketPath = process.env.COMPANY_MESH_SOCKET;
  if (!socketPath) {
    return Promise.reject(new RpcFailure({
      code: 'configuration_error',
      message: 'COMPANY_MESH_SOCKET is required.',
      retryable: false,
    }));
  }
  const id = randomUUID();
  const agentId = process.env.COMPANY_AGENT_ID || 'local-agent';
  return new Promise<T>((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let buffer = '';
    let settled = false;

    const finishError = (error: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(60_000, () => finishError(new RpcFailure({
      code: 'timeout', message: 'companyd did not respond within 60 seconds.', retryable: true,
    })));
    socket.on('error', error => finishError(new RpcFailure({
      code: 'daemon_unavailable', message: error.message, retryable: true,
    })));
    socket.on('connect', () => {
      socket.write(`${JSON.stringify({ id, method, params, agent_id: agentId })}\n`);
    });
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      const line = buffer.slice(0, newline);
      let response: RpcResponse;
      try {
        response = JSON.parse(line) as RpcResponse;
      } catch (error) {
        finishError(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      if (response.id !== id) {
        finishError(new Error('companyd returned a mismatched request ID.'));
        return;
      }
      settled = true;
      socket.end();
      if (!response.ok || response.error) {
        reject(new RpcFailure(response.error ?? {
          code: 'unknown_error', message: 'companyd returned an unknown error.', retryable: false,
        }));
        return;
      }
      resolve(response.result as T);
    });
  });
}

