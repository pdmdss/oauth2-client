export class BASE64URL {
  static encode(val: string | Uint8Array): string {
    if (ArrayBuffer.isView(val)) {
      return BASE64URL.encode(String.fromCharCode(...val));
    }

    return btoa(val)
      .replace(/[+/=]/g, m => m === '+' ? '-' : m === '/' ? '_' : '');
  }
}
