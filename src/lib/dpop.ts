import { JWT } from './jwt';
import { nanoid } from 'nanoid';
import { webCryptoAlgorithmGenerateKey, webCryptoAlgorithmImportKey } from './webcrypto.algorithms';
import { DPoPAlgorithm, DPoPAlgorithmName, Keypair } from '../types';
import { sha256Digest } from './hash';

export class DPoP {
  private constructor(private algorithm: DPoPAlgorithm, private privateKey: CryptoKey, private publicKey: CryptoKey) {
  }

  static async create(data: DPoPAlgorithm | DPoPAlgorithmName | Keypair) {
    if (typeof data === 'object' && 'privateKey' in data && 'publicKey' in data) {
      const params = webCryptoAlgorithmImportKey(data.alg) !;

      const privateKey = await window.crypto.subtle.importKey(
        'jwk',
        data.privateKey,
        params,
        true,
        ['sign']
      );
      const publicKey = await window.crypto.subtle.importKey(
        'jwk',
        data.publicKey,
        params,
        true,
        ['verify']
      );

      return new DPoP(data.alg, privateKey, publicKey);
    }
    if (typeof data === 'string') {
      data = { alg: data };
    }

    const keyPair = await window.crypto.subtle.generateKey(
      webCryptoAlgorithmGenerateKey(data.alg)!,
      true,
      ['sign', 'verify']
    );

    if (!('privateKey' in keyPair && 'publicKey' in keyPair) || !keyPair.privateKey || !keyPair.publicKey) {
      return null;
    }

    return new DPoP(data.alg, keyPair.privateKey, keyPair.publicKey);
  }

  async getDPoPProofJWT(method: string, uri: string, token?: string, nonce?: string) {
    const jwk = await window.crypto.subtle.exportKey('jwk', this.publicKey);

    return JWT.encode(
      {
        typ: 'dpop+jwt',
        alg: this.algorithm,
        jwk: {
          kty: jwk.kty,
          x: jwk.x,
          y: jwk.y,
          crv: jwk.crv,
          k: jwk.k,
          e: jwk.e,
          n: jwk.n
        }
      },
      {
        jti: nanoid(12),
        htm: method,
        htu: uri,
        iat: Math.floor((Date.now() / 1000)),
        ath: token && await sha256Digest(token),
        nonce
      }
    )
      .sign(this.privateKey)
      .then(jwt => jwt.toString());
  }

  async getDPoPKeypair(): Promise<Keypair> {
    const publicKey = await window.crypto.subtle.exportKey('jwk', this.publicKey);
    const privateKey = await window.crypto.subtle.exportKey('jwk', this.privateKey);

    return {
      alg: this.algorithm,
      privateKey,
      publicKey
    };
  }
}
