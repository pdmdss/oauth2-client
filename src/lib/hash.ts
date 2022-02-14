import { BASE64URL } from './base64';

export async function sha256Digest(msg: string) {
  const encoder = new TextEncoder();

  return BASE64URL.encode(
    new Uint8Array(
      await window.crypto.subtle.digest({ name: 'SHA-256' }, encoder.encode(msg).buffer
      )
    )
  );
}
