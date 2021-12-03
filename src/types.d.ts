export class OAuth2 {
  constructor(option: OAuth2Option);

  getAuthorization(): Promise<string>;
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
  refreshToken?: string;
  pkce?: 'S256' | 'plain' | true;
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

export interface SubWindowDetails {
  state: string;
  authCode?: string;
  errorCode?: string;
}
