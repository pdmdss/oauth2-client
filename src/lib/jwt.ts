import { JWTAlgorithm } from '../types';
import { BASE64URL } from './base64';
import { webCryptoAlgorithmSign } from './webcrypto.algorithms';

export interface JWTHeader {
  typ: string;
  alg: JWTAlgorithm;

  [key: string]: any;
}

export class JWT {
  static encode(header: JWTHeader, payload: Record<string, any>) {
    return new JWTEncode(header, JSON.stringify(payload));
  }
}

class JWTEncode {
  constructor(private header: JWTHeader, private payload: string, private signature: Uint8Array | null = null) {
  }

  async sign(key: CryptoKey) {
    const encoder = new TextEncoder();
    const signature = await window.crypto.subtle.sign(
        webCryptoAlgorithmSign(this.header.alg)!,
        key,
        encoder.encode(this.toString().slice(0, -1))
    );

    return new JWTEncode(this.header, this.payload, new Uint8Array(signature));
  }

  toString() {
    const items = [
      BASE64URL.encode(JSON.stringify(this.header)),
      BASE64URL.encode(this.payload),
      this.signature ? BASE64URL.encode(this.signature) : ''
    ];

    return items.join('.');
  }
}
