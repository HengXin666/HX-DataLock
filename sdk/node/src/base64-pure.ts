const TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += TABLE[(triple >> 18) & 63];
    out += TABLE[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? TABLE[(triple >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? TABLE[triple & 63] : '=';
  }
  return out;
}

export function base64ToBytes(text: string): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);
  if (text.length % 4 !== 0) {
    throw new Error('invalid base64');
  }
  const decoded = decodeUnchecked(text);
  if (bytesToBase64(decoded) !== text) throw new Error('invalid base64');
  return decoded;
}

function decodeUnchecked(text: string): Uint8Array {
  const pad = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - pad);
  let offset = 0;
  for (let i = 0; i < text.length; i += 4) {
    const n =
      (value(text.charCodeAt(i)) << 18) |
      (value(text.charCodeAt(i + 1)) << 12) |
      (value(text.charCodeAt(i + 2)) << 6) |
      value(text.charCodeAt(i + 3));
    out[offset++] = (n >> 16) & 255;
    if (offset < out.length) out[offset++] = (n >> 8) & 255;
    if (offset < out.length) out[offset++] = n & 255;
  }
  return out;
}

function value(code: number): number {
  if (code === 61) return 0;
  const index = TABLE.indexOf(String.fromCharCode(code));
  if (index < 0) throw new Error('invalid base64');
  return index;
}

export function sha256Base64Url(digest: Uint8Array): string {
  return bytesToBase64(digest).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
