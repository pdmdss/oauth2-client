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
  refreshToken?: string;
  pkce?: 'S256' | 'plain' | true;
  waitingStart?: boolean;
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
  refresh_token: string;
  scope: string;
}

export type OAuth2IntrospectEndpoint = {
  active: true;
  scope: string;
  client_id: string;
  aud: string;
  sub: string;
  username: string;
  iss: string;
  iat: number;
  exp: number;
} | {
  active: false;
}

export interface SubWindowDetails {
  state: string;
  authCode?: string;
  errorCode?: string;
}
