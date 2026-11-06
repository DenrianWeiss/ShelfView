export function agentOrigin(value) {
  const url = new URL(String(value));
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/') throw new Error('invalid_agent_origin');
  return url.origin;
}
