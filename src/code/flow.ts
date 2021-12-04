import axios from 'axios';
import { nanoid } from 'nanoid';
import { OAuth2 } from '../oauth2';
import { sha256Digest } from '../lib/hash';
import { SubWindow } from './sub';
import { OAuth2CodeOption, OAuth2TokenEndpointAuthorizationCode, OAuth2TokenEndpointRefreshToken } from '../types';

export class OAuth2Code extends OAuth2 {
  constructor(private option: OAuth2CodeOption) {
    super(option);
  }

  async getAuthorization(): Promise<string> {
    if (this.accessToken && this.accessToken.exp > Date.now()) {
      return this.accessToken.token;
    }

    const accessToken = await this.getAccessToken();

    return accessToken.token;
  }

  getRefreshToken() {
    return this.option.refreshToken;
  }

  private async getAccessToken() {
    const { data } =
      typeof this.option.refreshToken === 'string' ?
        await this.refreshGetAccessToken(this.option.refreshToken) :
        await this.authorization();

    if (data.refresh_token) {
      this.option.refreshToken = data.refresh_token;
    }

    const exp = new Date();
    exp.setSeconds(exp.getSeconds() + data.expires_in);

    return this.accessToken = {
      token: `${data.token_type} ${data.access_token}`,
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

  private authorizationAccessToken(code: string, pkce: string | null) {
    return this.post<OAuth2TokenEndpointAuthorizationCode>({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.option.client.redirectUri,
      code_verifier: pkce
    });
  }

  private refreshGetAccessToken(refreshToken: string) {
    return this.post<OAuth2TokenEndpointRefreshToken>({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: this.option.client.scopes?.join(' ')
    });
  }

  private post<T>(form: Record<string, string | undefined | null>) {
    const formData = Object.entries(form).filter((r): r is [string, string] => typeof r[1] === 'string');

    return axios.post<T>(
      this.option.endpoint.token, new URLSearchParams(formData), {
        headers: {
          authorization: 'Basic ' + btoa(`${this.option.client.id}:${this.option.client.secret}`)
        }
      });
  }
}
