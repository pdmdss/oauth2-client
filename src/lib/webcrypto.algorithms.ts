import { JWTAlgorithm } from '../types';

export function webCryptoAlgorithmSign(alg: JWTAlgorithm) {
  const type = alg.substring(0, 2);
  const length = alg.substring(2);

  if (type === 'RS') {
    return 'RSASSA-PKCS1-v1_5';
  }
  if (type === 'PS') {
    return {
      name: 'RSA-PSS',
      saltLength: +length / 8,
    };
  }
  if (type === 'ES') {
    return {
      name: 'ECDSA',
      hash: {
        name: `SHA-${length}`
      },
    };
  }
  if (type === 'HS') {
    return 'HMAC';
  }

  return null;
}

export function webCryptoAlgorithmGenerateKey(alg: JWTAlgorithm) {
  const type = alg.substring(0, 2);

  const params = webCryptoAlgorithmImportKey(alg);
  if (params && 'hash' in params && typeof params.hash === 'string') {
    return {
      ...params,
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1])
    };
  }

  return params;
}


export function webCryptoAlgorithmImportKey(alg: JWTAlgorithm) {
  const type = alg.substring(0, 2);
  const length = alg.substring(2);

  if (type === 'RS') {
    return {
      name: 'RSASSA-PKCS1-v1_5',
      hash: `SHA-${length}`
    };
  }
  if (type === 'PS') {
    return {
      name: 'RSA-PSS',
      hash: `SHA-${length}`
    };
  }
  if (type === 'ES') {
    return {
      name: 'ECDSA',
      namedCurve: `P-${length}`
    };
  }
  if (type === 'HS') {
    return {
      name: 'HMAC',
      hash: {
        name: `SHA-${length}`
      }
    };
  }

  return null;
}
