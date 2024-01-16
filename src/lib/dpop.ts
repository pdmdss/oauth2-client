import { JWT } from './jwt';
import { nanoid } from 'nanoid';
import { webCryptoAlgorithmGenerateKey } from './webcrypto.algorithms';
import { DPoPAlgorithm, DPoPAlgorithmName, Keypair } from '../types';
import { sha256Digest } from './hash';

export class DPoP {
  private publicJWK?: Object;
  private sha256Thumbprint?: string;

  private constructor(private algorithm: DPoPAlgorithm, private keyPair: CryptoKeyPair) {
  }

  static async create(data: DPoPAlgorithm | DPoPAlgorithmName | Keypair) {
    if (typeof data === 'object' && 'keyPair' in data && 'privateKey' in data.keyPair && 'publicKey' in data.keyPair) {
      return new DPoP(data.alg, { publicKey: data.keyPair.publicKey, privateKey: data.keyPair.privateKey });
    }

    if (typeof data === 'string') {
      data = { alg: data };
    }

    const keyPair = await window.crypto.subtle.generateKey(
      webCryptoAlgorithmGenerateKey(data.alg)!,
      false,
      ['sign', 'verify']
    );

    if (!('privateKey' in keyPair && 'publicKey' in keyPair) || !keyPair.privateKey || !keyPair.publicKey) {
      return null;
    }

    return new DPoP(data.alg, keyPair);
  }

  async getDPoPProofJWT(method: string, uri: string, token?: string, nonce?: string) {

    return JWT.encode(
      {
        typ: 'dpop+jwt',
        alg: this.algorithm,
        jwk: this.getPublicJWK()
      },
      {
        jti: nanoid(12),
        htm: method,
        htu: uri,
        iat: ~~((Date.now() / 1000)),
        ath: token && await sha256Digest(token),
        nonce
      }
    )
      .sign(this.keyPair.privateKey)
      .then(jwt => jwt.toString());
  }

  async getDPoPKeypair(): Promise<Keypair> {
    return {
      alg: this.algorithm,
      keyPair: this.keyPair
    };
  }

  async toSHA256Thumbprint() {
    if (this.sha256Thumbprint) {
      return this.sha256Thumbprint;
    }

    const jwk = await window.crypto.subtle.exportKey('jwk', this.keyPair.publicKey);
    const member =
      jwk.kty === 'EC' ?
        { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } :
        jwk.kty === 'RSA' ?
          { e: jwk.e, kty: jwk.kty, n: jwk.n } :
          { k: jwk.k, kty: jwk.kty };

    return this.sha256Thumbprint = await sha256Digest(JSON.stringify(member));
  }

  private async getPublicJWK() {
    if (this.publicJWK) {
      return this.publicJWK;
    }

    const jwk = await window.crypto.subtle.exportKey('jwk', this.keyPair.publicKey);

    return this.publicJWK = {
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
      crv: jwk.crv,
      k: jwk.k,
      e: jwk.e,
      n: jwk.n
    };
  }
}
