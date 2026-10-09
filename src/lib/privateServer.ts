export type PrivateServerConfig = {
  address: string;
  port: number;
  publicKey: string;
  secure: boolean;
};

const STORAGE_KEY = 'telegram_private_server_config';
const QUERY_ADDRESS = 'private_ip';
const QUERY_PORT = 'private_port';
const QUERY_PUBLIC_KEY = 'private_public_key';
const QUERY_SECURE = 'private_secure';
const QUERY_CLEAR = 'private_server';

let cachedConfig: PrivateServerConfig | null | undefined;

function readStorage(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch{
    return null;
  }
}

function writeStorage(value: string | null) {
  try {
    if(value) localStorage.setItem(STORAGE_KEY, value);
    else localStorage.removeItem(STORAGE_KEY);
  } catch{}
}

function decodeKeyInput(value: string): string {
  const trimmed = value.trim();
  if(trimmed.startsWith('data:')) {
    const comma = trimmed.indexOf(',');
    if(comma === -1) throw new Error('Invalid private server public key data URL');
    return new TextDecoder().decode(base64ToBytes(trimmed.slice(comma + 1)));
  }

  if(trimmed.includes('-----BEGIN')) return trimmed;

  const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  if(!normalized || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('Private server public key must be PEM or base64');
  }

  const decoded = new TextDecoder().decode(base64ToBytes(normalized));
  if(decoded.includes('-----BEGIN')) return decoded;
  throw new Error('Private server public key must contain a PEM block');
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for(let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let result = '';
  for(const byte of bytes) result += byte.toString(16).padStart(2, '0');
  return result;
}

function readDerLength(bytes: Uint8Array, offset: number): {length: number, next: number} {
  if(offset >= bytes.length) throw new Error('Truncated DER length');
  const first = bytes[offset++];
  if(first < 0x80) return {length: first, next: offset};
  const count = first & 0x7f;
  if(!count || count > 4 || offset + count > bytes.length) throw new Error('Invalid DER length');
  let length = 0;
  for(let i = 0; i < count; i++) length = length * 256 + bytes[offset + i];
  return {length, next: offset + count};
}

function readDer(bytes: Uint8Array, offset: number): {tag: number, value: Uint8Array, next: number} {
  if(offset >= bytes.length) throw new Error('Truncated DER object');
  const tag = bytes[offset++];
  const length = readDerLength(bytes, offset);
  const end = length.next + length.length;
  if(end > bytes.length) throw new Error('Truncated DER value');
  return {tag, value: bytes.subarray(length.next, end), next: end};
}

function readDerSequence(bytes: Uint8Array, offset = 0) {
  const object = readDer(bytes, offset);
  if(object.tag !== 0x30) throw new Error('Expected DER sequence');
  const items: Uint8Array[] = [];
  let cursor = 0;
  while(cursor < object.value.length) {
    const item = readDer(object.value, cursor);
    items.push(item.value);
    cursor = item.next;
  }
  return items;
}

function stripLeadingZero(value: Uint8Array): Uint8Array {
  let start = 0;
  while(start + 1 < value.length && value[start] === 0) start++;
  return value.subarray(start);
}

function parsePublicKey(pem: string): {modulus: string, exponent: string} {
  const match = pem.match(/-----BEGIN (?:RSA )?PUBLIC KEY-----([\s\S]*?)-----END (?:RSA )?PUBLIC KEY-----/);
  if(!match) throw new Error('Missing PEM public key markers');
  const der = base64ToBytes(match[1].replace(/\s+/g, ''));
  let parsed = readDerSequence(der);

  if(match[0].startsWith('-----BEGIN PUBLIC KEY-----')) {
    if(parsed.length !== 2) throw new Error('Invalid SubjectPublicKeyInfo');
    const bitString = parsed[1];
    if(!bitString.length || bitString[0] !== 0) {
      throw new Error('Invalid RSA SubjectPublicKeyInfo bit string');
    }
    parsed = readDerSequence(bitString.subarray(1));
  }

  if(parsed.length !== 2) throw new Error('Invalid RSA public key');
  const modulus = stripLeadingZero(parsed[0]);
  const exponent = stripLeadingZero(parsed[1]);
  if(modulus.length < 128 || modulus.length > 512) throw new Error('Unsupported RSA modulus size');
  if(exponent.length > 4) throw new Error('Unsupported RSA exponent');
  return {modulus: bytesToHex(modulus), exponent: bytesToHex(exponent)};
}

function normalizeAddress(address: string): string {
  const value = address.trim();
  if(!value || value.includes('/') || value.includes('@') || value.includes('?') || value.includes('#')) {
    throw new Error('Private server must be an IP address or hostname');
  }
  const host = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  if(!host || /[\s:/]/.test(host)) throw new Error('Invalid private server address');
  if(/^[0-9.]+$/.test(host)) {
    const parts = host.split('.');
    if(parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part) || +part > 255)) {
      throw new Error('Invalid IPv4 address');
    }
  }
  return host;
}

function normalizePort(port: string | number): number {
  const value = typeof port === 'number' ? port : Number(port);
  if(!Number.isInteger(value) || value < 1 || value > 65535) throw new Error('Invalid private server port');
  return value;
}

export function parsePrivateServerConfig(input: {
  address: string,
  port: string | number,
  publicKey: string,
  secure?: boolean
}): PrivateServerConfig {
  const parsedKey = parsePublicKey(decodeKeyInput(input.publicKey));
  return {
    address: normalizeAddress(input.address),
    port: normalizePort(input.port),
    publicKey: encodeKeyPem(parsedKey.modulus, parsedKey.exponent),
    secure: !!input.secure
  };
}

export function parsePublicPemHex(publicKey: string): {modulus: string, exponent: string} {
  return parsePublicKey(decodeKeyInput(publicKey));
}

function encodeKeyPem(modulusHex: string, exponentHex: string): string {
  const sequence = [
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00
  ];
  const pkcs1 = encodeRsaSequence(modulusHex, exponentHex);
  const bitString = encodeDer(0x03, Uint8Array.from([0, ...pkcs1]));
  const spkiContent = Uint8Array.from([...sequence, ...bitString]);
  const spki = encodeDer(0x30, spkiContent);
  const base64 = btoa(String.fromCharCode(...spki));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

function encodeRsaSequence(modulusHex: string, exponentHex: string): Uint8Array {
  const modulus = hexToBytes(modulusHex);
  const exponent = hexToBytes(exponentHex);
  const encodedModulus = encodeDer(0x02, withPositiveSign(modulus));
  const encodedExponent = encodeDer(0x02, withPositiveSign(exponent));
  return encodeDer(0x30, Uint8Array.from([...encodedModulus, ...encodedExponent]));
}

function withPositiveSign(bytes: Uint8Array): Uint8Array {
  return bytes.length && bytes[0] & 0x80 ? Uint8Array.from([0, ...bytes]) : bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for(let i = 0; i < result.length; i++) result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return result;
}

function encodeDer(tag: number, value: Uint8Array): Uint8Array {
  let length: number[] = [];
  if(value.length < 0x80) length = [value.length];
  else {
    const bytes: number[] = [];
    let rest = value.length;
    while(rest) {
      bytes.unshift(rest & 0xff);
      rest >>>= 8;
    }
    length = [0x80 | bytes.length, ...bytes];
  }
  return Uint8Array.from([tag, ...length, ...value]);
}

function queryConfig(): PrivateServerConfig | null {
  if(typeof location === 'undefined') return null;
  const params = new URLSearchParams(location.search);
  if(params.get(QUERY_CLEAR) === 'clear') {
    writeStorage(null);
    return null;
  }
  const address = params.get(QUERY_ADDRESS);
  const port = params.get(QUERY_PORT);
  const publicKey = params.get(QUERY_PUBLIC_KEY);
  if(!address && !port && !publicKey) return null;
  if(!address || !port || !publicKey) throw new Error('Incomplete private server query parameters');
  const config = parsePrivateServerConfig({
    address,
    port,
    publicKey,
    secure: params.get(QUERY_SECURE) === '1'
  });
  writeStorage(JSON.stringify(config));
  return config;
}

function loadConfig(): PrivateServerConfig | null {
  if(cachedConfig !== undefined) return cachedConfig;
  try {
    const fromQuery = queryConfig();
    if(fromQuery) return cachedConfig = fromQuery;
    const raw = readStorage();
    if(!raw) return cachedConfig = null;
    const parsed = JSON.parse(raw);
    return cachedConfig = parsePrivateServerConfig(parsed);
  } catch(error) {
    console.warn('Private server configuration ignored:', error);
    return cachedConfig = null;
  }
}

export function getPrivateServerConfig(): PrivateServerConfig | null {
  return loadConfig();
}

export function setPrivateServerConfig(config: PrivateServerConfig) {
  const normalized = parsePrivateServerConfig(config);
  writeStorage(JSON.stringify(normalized));
  cachedConfig = normalized;
}

export function clearPrivateServerConfig() {
  writeStorage(null);
  cachedConfig = null;
}

export function encodePrivateServerPublicKey(publicKey: string): string {
  const parsed = parsePublicKey(decodeKeyInput(publicKey));
  return encodeKeyPem(parsed.modulus, parsed.exponent);
}

export function privateServerHttpUrl(config: PrivateServerConfig): string {
  const host = config.address.includes(':') ? `[${config.address}]` : config.address;
  return `${config.secure ? 'https' : 'http'}://${host}:${config.port}/apiw1`;
}

export function privateServerAccountKey(config: PrivateServerConfig, accountNumber: number): string {
  const identity = `${config.secure ? 'https' : 'http'}://${config.address}:${config.port}\n${config.publicKey}`;
  let hash = 2166136261;
  for(const character of identity) {
    hash ^= character.codePointAt(0) || 0;
    hash = Math.imul(hash, 16777619);
  }

  const address = config.address.replace(/[^a-zA-Z0-9._-]/g, '_');
  const digest = (hash >>> 0).toString(16).padStart(8, '0');
  return `private-${address}-${config.port}-${digest}-account${accountNumber}`;
}
