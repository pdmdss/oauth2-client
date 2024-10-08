import { DPoP } from '../lib/dpop';
import { sha256Digest } from '../lib/hash';
import { OAuth2 } from '../oauth2';
import {
  DPoPAlgorithm,
  DPoPAlgorithmName,
  Keypair,
  OAuth2CodeOption,
  OAuth2TokenEndpointAuthorizationCode,
  OAuth2TokenEndpointRefreshToken
} from '../types';
import { SubWindow } from './sub';

export class OAuth2Code extends OAuth2 {
  private waiting = this.option.waitingStart ?? false;
  private refresh_token: string | null = null;
  private dpop: DPoP | null = null;

  constructor(private option: OAuth2CodeOption) {
    super(option);
  }

  emit(event: 'refresh_token', refreshToken: string): boolean;
  emit(event: 'dpop_keypair', keypair: Keypair): boolean;
  emit(event: string, ...args: any[]): boolean {
    return super.emit(event, ...args);
  }

  on(event: 'refresh_token', listener: (refreshToken: string) => void): this;
  on(event: 'dpop_keypair', listener: (keypair: Keypair) => void): this;
  on(event: string, listener: (...args: any[]) => void): this {
    return super.on(event, listener);
  }

  once(event: 'refresh_token', listener: (refreshToken: string) => void): this;
  once(event: 'dpop_keypair', listener: (keypair: Keypair) => void): this;
  once(event: string, listener: (...args: any[]) => void): this {
    return super.once(event, listener);
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

    const token = type === 'refresh_token' ? this.refresh_token : this.accessToken?.access_token;

    if (!token) {
      return true;
    }

    await this.post(endpoint, { token: token });

    return true;
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

    const refreshToken = this.option.refreshToken instanceof Promise ?
                         await this.option.refreshToken : this.option.refreshToken;

    const data =
      typeof refreshToken === 'string' ?
        await this.refreshGetAccessToken(refreshToken) :
        await this.authorization();

    const allowedScopes = data.scope.split(/\s/);
    if (this.option.client.scopes?.every(scope => allowedScopes.includes(scope)) === false) {
      this.option.refreshToken = undefined;
      return Promise.reject();
    }

    if ('refresh_token' in data) {
      this.option.refreshToken = data.refresh_token;
      this.emit('refresh_token', data.refresh_token);
    } else {
      this.refresh_token ??= refreshToken ?? null;
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
    const state = window.crypto.randomUUID();

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

      pkce = window.crypto.randomUUID();

      query.set('code_challenge', await sha256Digest(pkce));
      query.set('code_challenge_method', this.option.pkce);
    }

    if (this.option.client.scopes) {
      query.set('scope', this.option.client.scopes.join(' '));
    }
    if (this.option.client.redirectUri) {
      query.set('redirect_uri', this.option.client.redirectUri);
    }

    if (this.option.dpop) {
      const optionDPoP = this.option.dpop instanceof Promise ? await this.option.dpop : this.option.dpop;

      const DPoP = await this.createDPoP(typeof optionDPoP === 'string' ?
        { alg: optionDPoP } : { alg: optionDPoP.alg });

      if (DPoP) {
        this.emit('dpop_keypair', await DPoP.getDPoPKeypair());
        query.set('dpop_jkt', await DPoP.toSHA256Thumbprint());
      }
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
    return await this.requestWithDPoP<OAuth2TokenEndpointAuthorizationCode>(
      this.option.endpoint.token,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.option.client.redirectUri,
        code_verifier: pkce
      }
    );
  }

  private async refreshGetAccessToken(refreshToken: string) {
    if (!this.dpop && this.option.dpop) {
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

  private async requestWithDPoP<T>(url: string, form: Record<string, string | undefined | null>, nonce?: string): Promise<T> {
    const dpop = await this.getDPoPProofJWT('POST', url, nonce, false);

    const response = await this.post<T>(url, form, { ...(dpop ? { dpop } : {}) });
    const data = await response.json().catch(() => null);

    if (response.status > 299) {
      const dpopNonce = response.headers.get('dpop-nonce');
      if (!data || typeof data !== 'object' || data.error !== 'use_dpop_nonce' || typeof dpopNonce !== 'string') {
        return Promise.reject(data);
      }

      return this.requestWithDPoP(url, form, dpopNonce);
    }

    return data;
  }

  private post<T>(url: string, form: Record<string, string | undefined | null>, headers: Record<string, any> = {}) {
    const formData = Object.entries(form)
      .filter((r): r is [string, string] => typeof r[1] === 'string');

    return fetch(
      url,
      {
        method: 'post',
        body: new URLSearchParams(formData),
        headers: {
          ...headers,
          authorization: 'Basic ' + btoa(`${this.option.client.id}:${this.option.client.secret}`)
        }
      }
    );
  }

  private async createDPoP(data: DPoPAlgorithm | DPoPAlgorithmName | Keypair | Promise<DPoPAlgorithm | DPoPAlgorithmName | Keypair>) {
    return this.dpop = await DPoP.create(data instanceof Promise ? await data : data);
  }
}
