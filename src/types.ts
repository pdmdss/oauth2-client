export type JWTAlgorithm =
  'HS256' | 'HS384' | 'HS512' |
  'RS256' | 'RS384' | 'RS512' |
  'PS256' | 'PS384' | 'PS512' |
  'ES256' | 'ES384' | 'ES512';

export type DPoPAlgorithm = Exclude<JWTAlgorithm, 'HS256' | 'HS384' | 'HS512'>;

export interface DPoPAlgorithmName {
  alg: DPoPAlgorithm;
}

export interface Keypair {
  alg: DPoPAlgorithm;
  keyPair: CryptoKeyPair;
}


export interface OAuth2Client {
  id: string;
  secret?: string;
  redirectUri?: string;
  scopes?: string[];
}

export interface OAuth2Option {
  endpoint: {
    authorization: string;
    token: string;
    introspect?: string;
    revoke?: string;
  };
  client: OAuth2Client;
}

export interface OAuth2CodeOption extends OAuth2Option {
  refreshToken?: string | Promise<string | undefined>;
  pkce?: 'S256' | 'plain' | true;
  waitingStart?: boolean;
  dpop?: Keypair | DPoPAlgorithmName | DPoPAlgorithm | Promise<Keypair | DPoPAlgorithmName | DPoPAlgorithm>;
}

export interface OAuth2TokenEndpointAuthorizationCode {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export interface OAuth2TokenEndpointRefreshToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: never;
  scope: string;
}

export interface SubWindowDetails {
  state: string;
  authCode?: string;
  errorCode?: string;
}
