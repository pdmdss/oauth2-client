import { OAuth2Option } from './types';

export class OAuth2 {
  protected accessToken?: {
    token: string;
    exp: number;
  };

  constructor(option: OAuth2Option) {
  }


  getAuthorization(): Promise<string> {
    throw new Error('No access token.');
  }
}
