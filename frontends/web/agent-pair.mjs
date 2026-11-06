import { agentOrigin } from './agent-origin.mjs';
export async function pairAgent({ agentOrigin: originValue, secret, name = 'desktop', fetchImpl = fetch, timeoutMs = 10000 }) {
  const origin = agentOrigin(originValue);
  if (typeof secret !== 'string' || !/^[0-9a-f]{64}$/.test(secret)) throw new Error('invalid_pairing_secret');
  if (typeof name !== 'string' || !name.length || name.length > 120) throw new Error('invalid_client_name');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new Error('invalid_timeout');
  const response = await fetchImpl(new URL('/v1/pair', origin), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'error',
    body: JSON.stringify({ secret, name }), signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error('pairing_rejected');
  const result = await response.json();
  if (!result || typeof result.client_id !== 'string' || !/^[0-9a-f]{32}$/.test(result.client_id) ||
      typeof result.token !== 'string' || !/^[0-9a-f]{64}$/.test(result.token)) throw new Error('invalid_pairing_result');
  return { clientId: result.client_id, token: result.token };
}
