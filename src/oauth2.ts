import { OAuth2Option } from './types';
import { Events } from './lib/events';

export class OAuth2 extends Events {
  protected accessToken?: {
    access_token: string;
    token_type: string;
    exp: number;
  };

  constructor(option: OAuth2Option) {
    super();
  }


  getAuthorization(): Promise<string> {
    throw new Error('No access token.');
  }
}
