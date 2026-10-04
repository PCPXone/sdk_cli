/** Bound an untrusted download while streaming, before Blob/KDF processing. */
export async function readEncryptedResponse(response: Response): Promise<Blob> {
  const limit = 64 * 1024 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    await response.body?.cancel();
    throw new Error('CONTAINER_INVALID');
  }
  if (!response.body) throw new Error('CONTAINER_INVALID');
  const reader = response.body.getReader();
  const parts: Blob[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('CONTAINER_INVALID');
      parts.push(new Blob([value as BlobPart]));
    }
    return new Blob(parts, { type: 'application/octet-stream' });
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
}
