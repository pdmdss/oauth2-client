import axios from 'axios';
import {
  OAuth2,
  OAuth2CodeOption,
  OAuth2TokenEndpointAuthorizationCode,
  OAuth2TokenEndpointRefreshToken
} from '@/types';
import { nanoid } from 'nanoid';
import { SubWindow } from '@/code/sub';

export class OAuth2Code implements OAuth2 {
  private accessToken?: {
    token: string;
    exp: number;
  };

  constructor(private option: OAuth2CodeOption) {
  }

  async getAuthorization(): Promise<string> {
    if (this.accessToken && this.accessToken.exp > Date.now()) {
      return this.accessToken.token;
    }

    const accessToken = await this.getAccessToken();

    return accessToken.token;
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

    return this.authorizationAccessToken(authCode);
  }

  private authorizationAccessToken(code: string) {
    return this.post<OAuth2TokenEndpointAuthorizationCode>({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.option.client.redirectUri ?? ''
    });
  }

  private refreshGetAccessToken(refreshToken: string) {
    return this.post<OAuth2TokenEndpointRefreshToken>({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: this.option.client.scopes?.join(' ') ?? ''
    });
  }

  private post<T>(form: Record<string, string>) {
    return axios.post<T>(
      this.option.endpoint.token, new URLSearchParams(form), {
        headers: {
          authorization: 'Basic ' + btoa(`${this.option.client.id}:${this.option.client.secret}`)
        }
      });
  }
}
