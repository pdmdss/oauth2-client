import { OAuth2Option } from './types';

export class OAuth2 {
  protected accessToken?: {
    access_token: string;
    token_type: string;
    exp: number;
  };

  constructor(option: OAuth2Option) {
  }


  getAuthorization(): Promise<string> {
    throw new Error('No access token.');
  }
}
