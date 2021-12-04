import { SubWindowDetails } from '../types';

export class SubWindow {
  static SHARE_OBJECT_PREFIX = 'oauth2.code.flow';
  private subWindow?: Window;

  private constructor(private url: string, private details: SubWindowDetails) {
  }

  static open(url: string, details: SubWindowDetails) {
    const context = new this(url, details);

    return context.open();
  }

  async open() {
    const sub = window.open(this.url, 'sub-window', 'width=600,height=700');

    if (!sub) {
      throw new Error('I tried to open a sub window, but it failed.');
    }

    this.subWindow = sub;
    const share = this.details;

    // @ts-ignore
    window[`${SubWindow.SHARE_OBJECT_PREFIX}-${share.state}`] = share;

    return this.closeCheckInterval()
      .then(() => share);
  };

  private closeCheckInterval() {
    return new Promise<void>((resolve, reject) => {
      console.log(this.isSubWindowOpen());
      if (!this.isSubWindowOpen()) {
        console.log('sub window closed or not sub window open.');
        return reject();
      }

      const interval = setInterval(() => {
        if (this.isSubWindowOpen()) {
          return;
        }

        console.log('sub window close event');
        clearInterval(interval);
        resolve();
      }, 100);
    });
  }

  private isSubWindowOpen() {
    return this.subWindow?.closed === false;
  }
}

export class SubWindowMode {
  private constructor() {
  }

  static get isSubWindowMode() {
    return window.opener?.closed === false;
  }

  static start() {
    if (!SubWindowMode.isSubWindowMode) {
      return false;
    }

    this.initSubWindowMode();
    this.openerCloseCheckInterval();

    return true;
  }

  private static initSubWindowMode() {
    const param = new URLSearchParams(window.location.hash.slice(1));
    const state = param.get('state');

    // @ts-ignore
    const share: SubWindowDetails = window.opener[`${SubWindow.SHARE_OBJECT_PREFIX}-${state}`];

    if (share) {
      share.authCode = param.get('code') ?? undefined;
      share.errorCode = param.get('error') ?? undefined;
    }

    window.close();
  }

  private static openerCloseCheckInterval() {
    setInterval(() => {
      if (window.opener?.closed === false) {
        return;
      }

      window.close();
    }, 100);
  }
}
