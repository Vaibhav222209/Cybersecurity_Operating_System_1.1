// Hash + encoding helpers shared by the terminal and the Crypto Toolkit.

export function md5(str: string): string {
  const bytes = new TextEncoder().encode(str);
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const len = bytes.length;
  const padLen = (((len + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(bytes);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, (len * 8) >>> 0, true);
  dv.setUint32(padLen - 4, Math.floor((len * 8) / 4294967296), true);
  let a0 = 0x67452301,
    b0 = 0xefcdab89,
    c0 = 0x98badcfe,
    d0 = 0x10325476;
  for (let off = 0; off < padLen; off += 64) {
    const M = Array.from({ length: 16 }, (_, i) => dv.getUint32(off + i * 4, true));
    let A = a0,
      B = b0,
      C = c0,
      D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0].map((w) => [0, 1, 2, 3].map((j) => ((w >>> (8 * j)) & 255).toString(16).padStart(2, "0")).join("")).join("");
}

export type ShaAlgo = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export async function sha(algo: ShaAlgo, s: string): Promise<string> {
  if (!globalThis.crypto?.subtle) return "(WebCrypto unavailable in this context)";
  const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64enc(s: string) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
export function b64dec(s: string) {
  const bin = atob(s.trim());
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
export function toHex(s: string) {
  return [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}
export function fromHex(s: string) {
  const clean = s.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return new TextDecoder().decode(bytes);
}
export function rot13(s: string) {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const b = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
  });
}
export function toBinary(s: string) {
  return [...new TextEncoder().encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" ");
}

/* ---------- password strength ---------- */
export function passwordStats(pw: string) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "iloveyou", "sugreev", "abc123", "111111", "dragon", "monkey"];
  const isCommon = common.some((c) => pw.toLowerCase().includes(c));
  let entropy = pw.length * Math.log2(pool || 1);
  if (isCommon) entropy = Math.min(entropy, 20);
  if (/(.)\1{2,}/.test(pw)) entropy -= 6;
  if (/(012|123|234|345|456|567|678|789|abc|bcd|cde|def)/i.test(pw)) entropy -= 6;
  entropy = Math.max(0, entropy);
  const guesses = Math.pow(2, entropy);
  const secs = guesses / 2 / 1e10; // 10 billion guesses/sec (offline GPU rig, fast hash)
  return { pool, entropy, secs, isCommon };
}
export function humanTime(secs: number) {
  if (secs < 1) return "instantly";
  const units: [string, number][] = [["years", 31536000], ["days", 86400], ["hours", 3600], ["minutes", 60], ["seconds", 1]];
  if (secs > 31536000 * 1e9) return "billions of years+";
  for (const [n, v] of units) if (secs >= v) return `${Math.round(secs / v).toLocaleString()} ${n}`;
  return "instantly";
}
export function genPassword(len = 20, symbols = true) {
  const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789" + (symbols ? "!@#$%^&*()-_=+[]{}" : "");
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((n) => set[n % set.length]).join("");
}
