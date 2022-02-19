import axios, { AxiosRequestHeaders, AxiosResponse } from 'axios';
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

  async getAuthorization(): Promise<string>;
  async getAuthorization(isRaw: true): Promise<{ access_token: string; token_type: string; exp: number }>;
  async getAuthorization(isRaw?: true): Promise<string | { access_token: string; token_type: string; exp: number }> {
    const accessToken = await this.getAccessToken();

    if (isRaw) {
      return { ...accessToken };
    }

    return `${accessToken.token_type} ${accessToken.access_token}`;
  }

  getDPoPKeypair() {
    return this.dpop?.getDPoPKeypair();
  }

  async getDPoPProofJWT(method: string, uri: string, nonce?: string | null, isTokenInclude = true) {
    const token = isTokenInclude ? await this.getAuthorization(true)
                                             .then(e => e.access_token) : undefined;

    const jwt = await this.dpop?.getDPoPProofJWT(method, uri, token, nonce ?? undefined);

    if (!jwt) {
      return null;
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

  async revoke(type: 'access_token' | 'refresh_token' = 'access_token') {
    const endpoint = this.option.endpoint.revoke;

    if (!endpoint) {
      return false;
    }

    const token = type === 'refresh_token' ? this.option.refreshToken : this.accessToken?.access_token;

    if (!token) {
      return true;
    }

    await this.post(endpoint, { token: token });

    return true;
  }

  async introspect(type: 'access_token' | 'refresh_token' = 'access_token') {
    const endpoint = this.option.endpoint.introspect;

    if (!endpoint) {
      return false;
    }

    const token = type === 'refresh_token' ? this.option.refreshToken : this.accessToken?.access_token;

    if (!token) {
      return null;
    }

    return this.post<OAuth2IntrospectEndpoint>(endpoint, { token: token });
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
    if (this.accessToken && this.accessToken.exp > Date.now()) {
      return this.accessToken;
    }

    if (this.waiting) {
      await this.authorizationWaiting();
    }

    this.startWait();

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

    this.endWait();

    return this.accessToken = {
      access_token: data.access_token,
      token_type: data.token_type,
      exp: exp.getTime()
    };
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
    if (this.option.dpop) {
      await this.createDPoP(typeof this.option.dpop === 'string' ? { alg: this.option.dpop } : { alg: this.option.dpop.alg });
    }

    try {
      return await this.requestWithDPoP<OAuth2TokenEndpointAuthorizationCode>(
        this.option.endpoint.token,
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: this.option.client.redirectUri,
          code_verifier: pkce
        }
      );
    } finally {
      const keypair = await this.getDPoPKeypair();

      if (keypair) {
        this.emit('dpop_keypair', keypair);
      }
    }
  }

  private async refreshGetAccessToken(refreshToken: string) {
    if (this.option.dpop) {
      await this.createDPoP(this.option.dpop);
    }

    return await this.requestWithDPoP<OAuth2TokenEndpointRefreshToken>(
      this.option.endpoint.token,
      {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: this.option.client.scopes?.join(' ')
      }
    );
  }

  private async requestWithDPoP<T>(url: string, form: Record<string, string | undefined | null>,
                                   nonce?: string): Promise<AxiosResponse<T>> {
    const dpop = await this.getDPoPProofJWT('POST', url, nonce, false);

    const req = this.post<T>(url, form, { ...(dpop ? { dpop } : {}) });

    return await req.catch(error => {
      if (!error.response.data || typeof error.response.data !== 'object' || typeof error.response.headers['dpop-nonce'] !== 'string') {
        return Promise.reject(error);
      }

      return this.requestWithDPoP(url, form, error.response.headers['dpop-nonce']);
    });
  }

  private post<T>(url: string, form: Record<string, string | undefined | null>, headers: AxiosRequestHeaders = {}) {
    const formData = Object.entries(form)
                           .filter((r): r is [string, string] => typeof r[1] === 'string');

    return axios.post<T>
                (
                  url,
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
