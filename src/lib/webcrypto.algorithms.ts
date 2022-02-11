export type Algorithm =
  'HS256' | 'HS384' | 'HS512' |
  'RS256' | 'RS384' | 'RS512' |
  'PS256' | 'PS384' | 'PS512' |
  'ES256' | 'ES384' | 'ES512';

export function webCryptoAlgorithmSign(alg: Algorithm) {
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

export function webCryptoAlgorithmGenerateKey(alg: Algorithm) {
  const type = alg.substring(0, 2);
  const length = alg.substring(2);

  if (type === 'RS') {
    return {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: `SHA-${length}`
    };
  }
  if (type === 'PS') {
    return {
      name: 'RSA-PSS',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
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
