import axios, { AxiosRequestHeaders } from 'axios';
import { nanoid } from 'nanoid';
import { OAuth2 } from '../oauth2';
import { DPoP } from '../lib/dpop';
import { sha256Digest } from '../lib/hash';
import { SubWindow } from './sub';
import {
  DPoPAlgorithm,
  DPoPAlgorithmName,
  Keypair,
  OAuth2CodeOption,
  OAuth2IntrospectEndpoint,
  OAuth2TokenEndpointAuthorizationCode,
  OAuth2TokenEndpointRefreshToken
} from '../types';

export class OAuth2Code extends OAuth2 {
  private waiting = this.option.waitingStart ?? false;
  private dpop: DPoP | null = null;

  constructor(private option: OAuth2CodeOption) {
    super(option);
  }

  async getAuthorization(): Promise<string> {
    if (this.waiting) {
      await this.authorizationWaiting();
    }

    if (this.accessToken && this.accessToken.exp > Date.now()) {
      return this.accessToken.token;
    }

    this.startWait();

    const accessToken = await this.getAccessToken();

    this.endWait();

    return accessToken.token;
  }

  getDPoPKeypair() {
    return this.dpop?.getDPoPKeypair();
  }

  async getDPoPProofJWT(method: string, uri: string, isHeaderInclude: true): Promise<{ dpop: string } | null>;
  async getDPoPProofJWT(method: string, uri: string, isHeaderInclude?: false): Promise<string | null>;
  async getDPoPProofJWT(method: string, uri: string, isHeaderInclude = false) {
    const jwt = await this.dpop?.getDPoPProofJWT(method, uri);

    if (!jwt) {
      return null;
    }

    if (isHeaderInclude) {
      return { dpop: jwt };
    }

    return jwt;
  }

  startWait() {
    this.waiting = true;
  }

  getRefreshToken() {
    return this.option.refreshToken;
  }

  endWait() {
    this.waiting = false;
  }

  private authorizationWaiting() {
    return new Promise<void>(resolve => {
      const internal = setInterval(() => {
        if (this.waiting) {
          return;
        }

        clearInterval(internal);
        resolve();
      }, 50);
    });
  }

  private async getAccessToken() {
    if (this.option.dpop) {
      await this.createDPoP(this.option.dpop);
    }

    const { data } =
      typeof this.option.refreshToken === 'string' ?
        await this.refreshGetAccessToken(this.option.refreshToken) :
        await this.authorization();

    if (data.refresh_token) {
      this.option.refreshToken = data.refresh_token;
    }

    const exp = new Date();
    exp.setSeconds(exp.getSeconds() + data.expires_in);

    if (data.token_type !== 'DPoP') {
      this.dpop = null;
    }

    return this.accessToken = {
      token: `${data.token_type} ${data.access_token}`,
      exp: exp.getTime()
    };
  }

  private async revoke(type: 'access_token' | 'refresh_token' = 'access_token') {
    const endpoint = this.option.endpoint.revoke;

    if (!endpoint) {
      return false;
    }

    const token = type === 'refresh_token' ? this.option.refreshToken : this.accessToken?.token;

    if (!token) {
      return true;
    }

    await this.post(endpoint, { token: token });

    return true;
  }

  private async introspect(type: 'access_token' | 'refresh_token' = 'access_token') {
    const endpoint = this.option.endpoint.introspect;

    if (!endpoint) {
      return false;
    }

    const token = type === 'refresh_token' ? this.option.refreshToken : this.accessToken?.token;

    if (!token) {
      return null;
    }

    return this.post<OAuth2IntrospectEndpoint>(endpoint, { token: token });
  }

  private async authorization() {
    const state = nanoid(32);

    const url = new URL(this.option.endpoint.authorization);
    const query = url.searchParams;

    query.set('client_id', this.option.client.id);
    query.set('response_type', 'code');
    query.set('response_mode', 'fragment');
    query.set('state', state);

    let pkce: string | null = null;
    if (this.option.pkce) {
      if (this.option.pkce === true) {
        this.option.pkce = 'S256';
      }

      pkce = nanoid(43);

      query.set('code_challenge', await sha256Digest(pkce));
      query.set('code_challenge_method', this.option.pkce);
    }

    if (this.option.client.scopes) {
      query.set('scope', this.option.client.scopes.join(' '));
    }
    if (this.option.client.redirectUri) {
      query.set('redirect_uri', this.option.client.redirectUri);
    }

    const { authCode, errorCode } = await SubWindow.open(url.toString(), { state });

    if (!authCode || errorCode) {
      throw {
        mode: 'error',
        errorCode: errorCode ?? null
      };
    }

    return this.authorizationAccessToken(authCode, pkce);
  }

  private async authorizationAccessToken(code: string, pkce: string | null) {
    return await this.post<OAuth2TokenEndpointAuthorizationCode>(
      this.option.endpoint.token,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.option.client.redirectUri,
        code_verifier: pkce
      },
      {
        ...await this.getDPoPProofJWT('POST', this.option.endpoint.token, true)
      }
    );
  }

  private async refreshGetAccessToken(refreshToken: string) {
    return await this.post<OAuth2TokenEndpointRefreshToken>(
      this.option.endpoint.token,
      {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: this.option.client.scopes?.join(' ')
      },
      {
        ...await this.getDPoPProofJWT('POST', this.option.endpoint.token, true)
      }
    );
  }

  private post<T>(url: string, form: Record<string, string | undefined | null>, headers: AxiosRequestHeaders = {}) {
    const formData = Object.entries(form).filter((r): r is [string, string] => typeof r[1] === 'string');

    return axios.post<T>
    (url,
      new URLSearchParams(formData),
      {
        headers: {
          ...headers,
          authorization: 'Basic ' + btoa(`${this.option.client.id}:${this.option.client.secret}`)
        }
      });
  }

  private async createDPoP(data: DPoPAlgorithm | DPoPAlgorithmName | Keypair) {
    return this.dpop = await DPoP.create(data);
  }
}
