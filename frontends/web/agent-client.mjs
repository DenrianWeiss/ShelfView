import { agentOrigin } from './agent-origin.mjs';
import { publishFile } from './agent-media.mjs';

export class AgentError extends Error {
  constructor(code, result = null) {
    super(code); this.result = result;
  }
}

export class AgentClient {
  constructor({ agentOrigin: origin, token, fetchImpl = fetch, timeoutMs = 10000 }) {
    this.origin = agentOrigin(origin);
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) throw new AgentError('invalid_token');
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) throw new AgentError('invalid_timeout');
    this.token = token; this.fetch = (url, options) => fetchImpl(url, options); this.timeoutMs = timeoutMs;
  }
  async #request(path, method, body, mutating = true) {
    let response;
    const signal = AbortSignal.timeout(this.timeoutMs);
    try {
      response = await this.fetch(new URL(path, this.origin), {
        method, headers: { Authorization: `Bearer ${this.token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        cache: 'no-store', credentials: 'omit', redirect: 'error', signal,
      });
    } catch {
      throw new AgentError(mutating ? 'outcome_unknown' : signal.aborted ? 'timeout' : 'connection_failed');
    }
    let result;
    try { result = await response.json(); }
    catch {
      throw new AgentError(mutating ? 'outcome_unknown' : signal.aborted ? 'timeout' : 'invalid_response');
    }
    if (!response.ok) throw new AgentError(result?.error || `http_${response.status}`, result);
    if (!result || typeof result !== 'object' || Array.isArray(result) ||
        (mutating && (typeof result.status !== 'string' || !result.status)))
      throw new AgentError(mutating ? 'outcome_unknown' : 'invalid_response');
    if (result.status && result.status !== 'ok') throw new AgentError(result.status, result);
    return result;
  }
  async connect(deviceId = null) {
    if (deviceId !== null && (typeof deviceId !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(deviceId)))
      throw new AgentError('invalid_device_id');
    const result = await this.#request('/v1/connections', 'POST', {
      mode: 'auto', ...(deviceId === null ? {} : { device_id: deviceId }),
    });
    connectionPath(result.connection_id);
    if (deviceId !== null && result.device_id !== deviceId) {
      let cleanupConfirmed = false;
      try { await this.close(result.connection_id); cleanupConfirmed = true; } catch {}
      throw new AgentError('device_association_mismatch', { ...result, cleanupConfirmed });
    }
    return result;
  }
  close(id) { return this.#request(connectionPath(id), 'DELETE'); }
  query(id, operation, uri) {
    return this.#request(`${connectionPath(id)}/query`, 'POST', { operation, ...(uri === undefined ? {} : { uri }) }, false);
  }
  mountMedia(id, uri, imageUrl) {
    return this.#request(`${connectionPath(id)}/media`, 'POST', {
      media_uri: uri, image_url: imageUrl, write_protected: true,
    });
  }
  ejectMedia(id, uri) { return this.#request(`${connectionPath(id)}/media`, 'DELETE', uri === undefined ? undefined : { media_uri: uri }); }
  publishMediaFile(file) { return publishFile({ agentOrigin: this.origin, token: this.token, file, timeoutMs: this.timeoutMs, fetchImpl: this.fetch }); }
  mountFileMedia(id, uri, sourceId) {
    if (typeof sourceId !== 'string' || !/^[0-9a-f]{32}$/.test(sourceId)) throw new AgentError('invalid_media_source');
    return this.#request(`${connectionPath(id)}/media`, 'POST', { media_uri: uri, source_id: sourceId, write_protected: true });
  }
  boot(id, uri, target, mode = 'preserve') { return this.#request(`${connectionPath(id)}/boot`, 'POST', { uri, target, mode }); }
  power(id, uri, action) { return this.#request(`${connectionPath(id)}/power`, 'POST', { uri, action }); }
}

function connectionPath(id) {
  if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) throw new AgentError('invalid_connection_id');
  return `/v1/connections/${id}`;
}
