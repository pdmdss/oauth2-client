import { JWTAlgorithm } from '../types';

export function webCryptoAlgorithmSign(alg: JWTAlgorithm) {
  const { type, length } = algType(alg);

  if (type === 'RS') {
    return <const>'RSASSA-PKCS1-v1_5';
  }
  if (type === 'PS') {
    return <const>{
      name: 'RSA-PSS',
      saltLength: +length / 8,
    };
  }
  if (type === 'ES') {
    return <const>{
      name: 'ECDSA',
      hash: {
        name: `SHA-${length}`,
      },
    };
  }
  if (type === 'HS') {
    return <const>'HMAC';
  }

  return null;
}

export function webCryptoAlgorithmGenerateKey(alg: JWTAlgorithm) {
  const params =
    webCryptoAlgorithmImportKey(alg);

  if (params && 'hash' in params && (params.name === 'RSASSA-PKCS1-v1_5' || params.name === 'RSA-PSS')) {
    return {
      ...params,
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
    };
  }

  return params;
}


export function webCryptoAlgorithmImportKey(alg: JWTAlgorithm) {
  const { type, length } = algType(alg);

  if (type === 'RS') {
    return <const>{
      name: 'RSASSA-PKCS1-v1_5',
      hash: `SHA-${length}`,
    };
  }
  if (type === 'PS') {
    return <const>{
      name: 'RSA-PSS',
      hash: `SHA-${length}`,
    };
  }
  if (type === 'ES') {
    return <const>{
      name: 'ECDSA',
      namedCurve: `P-${length}`,
    };
  }
  if (type === 'HS') {
    return <const>{
      name: 'HMAC',
      hash: {
        name: `SHA-${length}`,
      },
    };
  }

  return null;
}

function algType(alg: JWTAlgorithm) {
  return {
    type: <'RS' | 'PS' | 'ES' | 'HS'>alg.substring(0, 2),
    length: <'256' | '384' | '512'>alg.substring(2),
  };
}
