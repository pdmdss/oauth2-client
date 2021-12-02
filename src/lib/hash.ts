import { enc, SHA256 } from 'crypto-js';

export async function sha256Digest(msg: string) {
  return SHA256(msg).toString(enc.Base64)
    .replace(/[+/=]/g, s => s === '+' ? '-' : s === '/' ? '_' : '');
}
