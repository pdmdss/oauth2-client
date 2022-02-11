import { JWT } from './jwt';
import { nanoid } from 'nanoid';
import { Algorithm, webCryptoAlgorithmGenerateKey } from './webcrypto.algorithms';

export type DPoPAlgorithm = Exclude<Algorithm, 'HS256' | 'HS384' | 'HS512'>;

export class DPoP {
  private constructor(private algorithm: DPoPAlgorithm, private privateKey: CryptoKey, private publicKey: CryptoKey) {
  }

  static async create(alg: DPoPAlgorithm = 'ES256') {
    const keyPair = await window.crypto.subtle.generateKey(
      webCryptoAlgorithmGenerateKey(alg)!,
      true,
      ['sign', 'verify']
    );

    if (!('privateKey' in keyPair && 'publicKey' in keyPair) || !keyPair.privateKey || !keyPair.publicKey) {
      return null;
    }

    return new DPoP(alg, keyPair.privateKey, keyPair.publicKey);
  }

  async getDPoPProofJWT(method: string, uri: string) {
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
        iat: Math.floor((Date.now() / 1000))
      }
    )
      .sign(this.privateKey)
      .then(jwt => jwt.toString());
  }
}
