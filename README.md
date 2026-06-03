# SecureRequest

ASP.NET Core middleware that adds a full **RSA + AES-256-GCM + HMAC-SHA256** security layer on top of TLS for `POST / PUT / PATCH` endpoints.

## What it does

| Feature | Description |
|---|---|
| **Body encryption** | Client AES-256-GCM encrypts the request body. Server decrypts before controller binding. |
| **HMAC signing** | Client signs a canonical string with HMAC-SHA256. Server verifies the `X-Signature` header. |
| **Timestamp check** | Rejects requests whose clock drift exceeds the configured tolerance (default ±5 min). |
| **Nonce anti-replay** | Each nonce is burned in the distributed cache (Redis / memory) after use. |
| **Dynamic key exchange** | No static secrets in config. Client generates fresh AES + HMAC keys per-request, RSA-encrypts them, and sends via `X-Encrypted-Key`. |
| **Load-balancer safe** | RSA key pair is persisted in the distributed cache on first startup — all instances share the same key. |

## Installation

```
dotnet add package SecureRequest
```

Requires `IDistributedCache` — add Redis or in-memory cache before calling `AddSecureRequest`.

## Quick start

```csharp
// Program.cs
builder.Services.AddDistributedMemoryCache(); // or AddStackExchangeRedisCache(...)
builder.Services.AddSecureRequest(builder.Configuration);

var app = builder.Build();
app.UseSecureRequest(); // before UseRouting / UseAuthorization
app.MapSecureRequestPublicKey(); // GET /api/secure/public-key
```

**appsettings.json**

```json
"SecureRequest": {
  "Enabled": true,
  "EnableBodyEncryption": true,
  "EnableHmacSigning": true,
  "TimestampToleranceSeconds": 300,
  "NonceCacheTtlSeconds": 700,
  "SecuredMethods": [ "POST", "PUT", "PATCH" ],
  "ExcludedPaths": [ "/api/secure/public-key" ]
}
```

## Configuration (consuming project)

The consuming project owns all settings — add the section to its own `appsettings.json` (and override per environment in `appsettings.Production.json`, `appsettings.Development.json`, etc.):

```json
"SecureRequest": {
  "Enabled": true,
  "EnableBodyEncryption": true,
  "EnableHmacSigning": true,
  "TimestampToleranceSeconds": 300,
  "NonceCacheTtlSeconds": 700,
  "SecuredMethods": [ "POST", "PUT", "PATCH" ],
  "ExcludedPaths": [ "/api/secure/public-key" ]
}
```

> **Tip:** Use a different section name? Pass it to `AddSecureRequest`:
> ```csharp
> builder.Services.AddSecureRequest(builder.Configuration, sectionName: "MyCustomSection");
> ```

| Setting | Default | Description |
|---|---|---|
| `Enabled` | `false` | Master switch. Set `true` in production, `false` in development/Swagger. |
| `EnableBodyEncryption` | `true` | AES-256-GCM encrypt the request body. |
| `EnableHmacSigning` | `true` | HMAC-SHA256 sign the canonical request string. |
| `TimestampToleranceSeconds` | `300` | Max allowed clock drift between client and server (seconds). |
| `NonceCacheTtlSeconds` | `700` | How long a used nonce is kept in cache to block replays. Must be > 2 × `TimestampToleranceSeconds`. |
| `SecuredMethods` | `POST, PUT, PATCH` | HTTP methods the pipeline enforces. Any other method is bypassed. |
| `ExcludedPaths` | `[]` | URL path segments (case-insensitive substring match) that bypass the pipeline entirely. Always include the public-key endpoint. |

## Feature flags

| `EnableBodyEncryption` | `EnableHmacSigning` | Effect |
|---|---|---|
| `true` | `true` | Full pipeline — recommended for production |
| `false` | `true` | Integrity only — body plaintext, signature verified |
| `true` | `false` | Confidentiality only — body encrypted, no signature |
| `false` | `false` | Anti-replay only — timestamp + nonce checked |
| `Enabled: false` | — | Bypass everything (development / Swagger) |

## Security headers

| Header | Direction | Purpose |
|---|---|---|
| `X-Timestamp` | Client → Server | Unix timestamp (seconds) |
| `X-Nonce` | Client → Server | Random UUID per request |
| `X-Encrypted-Key` | Client → Server | RSA-OAEP-SHA256 encrypted 64-byte secret (AES key + HMAC key) |
| `X-Signature` | Client → Server | HMAC-SHA256 over canonical string |

## Frontend integration

Zero npm dependencies — uses the native browser **Web Crypto API** available in all modern browsers.

### TypeScript

#### `secureRequestService.ts`

```ts
const API_BASE_URL    = process.env.REACT_APP_API_URL as string;
const PUBLIC_KEY_PATH = '/api/secure/public-key';

// Feature flags — must match appsettings SecureRequest section
export const SECURE_ENABLE_BODY_ENCRYPTION =
  (process.env.REACT_APP_SECURE_BODY_ENCRYPTION ?? 'true') === 'true';
export const SECURE_ENABLE_HMAC_SIGNING =
  (process.env.REACT_APP_SECURE_HMAC_SIGNING ?? 'true') === 'true';

export interface SecureRequestResult {
  encryptedBody: string;
  headers: {
    'X-Timestamp':     string;
    'X-Nonce':         string;
    'X-Signature':     string;
    'X-Encrypted-Key': string;
  };
}

// ── RSA public key cache ───────────────────────────────────────────────────────
let _cachedRsaPublicKey: CryptoKey | null = null;

export async function getServerPublicKey(): Promise<CryptoKey> {
  if (_cachedRsaPublicKey) return _cachedRsaPublicKey;

  const response = await fetch(`${API_BASE_URL}${PUBLIC_KEY_PATH}`);
  if (!response.ok) throw new Error(`[SecureRequest] Failed to fetch RSA public key: ${response.status}`);

  const data = await response.json();
  // Server returns { publicKey: "BASE64..." }
  const publicKeyBase64: string = data?.publicKey ?? data?.result ?? data;
  const publicKeyBytes = base64ToBytes(publicKeyBase64);

  _cachedRsaPublicKey = await crypto.subtle.importKey(
    'spki', publicKeyBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false, ['encrypt']
  );
  return _cachedRsaPublicKey;
}

export function clearPublicKeyCache(): void {
  _cachedRsaPublicKey = null;
}

// ── Byte helpers ───────────────────────────────────────────────────────────────
function base64ToBytes(base64: string): Uint8Array {
  let normalized = base64.trim().replace(/-/g, '+').replace(/_/g, '/');
  const rem = normalized.length % 4;
  if (rem) normalized += '='.repeat(4 - rem);
  const binary = atob(normalized);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ── Per-request key generation ─────────────────────────────────────────────────
async function generateRequestKeys() {
  const secret       = crypto.getRandomValues(new Uint8Array(64));
  const rawAesBytes  = secret.slice(0, 32);
  const rawHmacBytes = secret.slice(32);

  const [aesKey, hmacKey] = await Promise.all([
    crypto.subtle.importKey('raw', rawAesBytes,  { name: 'AES-GCM' },              false, ['encrypt']),
    crypto.subtle.importKey('raw', rawHmacBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
  ]);
  return { aesKey, hmacKey, rawAesBytes, rawHmacBytes };
}

// ── AES-256-GCM body encryption ────────────────────────────────────────────────
async function encryptBody(body: unknown, aesKey: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(
    typeof body === 'string' ? body : JSON.stringify(body)
  );
  const ciphertextWithTag = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, aesKey, plaintext
  );
  const result = new Uint8Array(iv.length + ciphertextWithTag.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertextWithTag), iv.length);
  return { encryptedBytes: result, encryptedBase64: bytesToBase64(result) };
}

// ── Body hash ──────────────────────────────────────────────────────────────────
async function computeBodyHash(bytes: Uint8Array | null): Promise<string> {
  if (!bytes || bytes.length === 0)
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

// ── HMAC signature ─────────────────────────────────────────────────────────────
async function computeSignature(
  method: string, path: string, query: string,
  timestamp: string, nonce: string, bodyHash: string,
  hmacKey: CryptoKey
): Promise<string> {
  const canonical = [method.toUpperCase(), path, query, timestamp, nonce, bodyHash].join('\n');
  const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(canonical));
  return bytesToBase64(new Uint8Array(sig));
}

// ── RSA encrypt 64-byte secret ─────────────────────────────────────────────────
async function encryptSecretKey(rawAesBytes: Uint8Array, rawHmacBytes: Uint8Array): Promise<string> {
  const combined = new Uint8Array(64);
  combined.set(rawAesBytes, 0);
  combined.set(rawHmacBytes, 32);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, await getServerPublicKey(), combined
  );
  return bytesToBase64(new Uint8Array(encrypted));
}

// ── Public API ─────────────────────────────────────────────────────────────────
export async function buildSecureRequest(
  method: string, path: string, query: string, body: unknown
): Promise<SecureRequestResult> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomUUID();

  const needKeys = SECURE_ENABLE_BODY_ENCRYPTION || SECURE_ENABLE_HMAC_SIGNING;
  const keys     = needKeys ? await generateRequestKeys() : null;

  let encryptedBase64 = '';
  let encryptedBytes: Uint8Array | null = null;

  if (SECURE_ENABLE_BODY_ENCRYPTION && keys && body != null) {
    const result    = await encryptBody(body, keys.aesKey);
    encryptedBase64 = result.encryptedBase64;
    encryptedBytes  = result.encryptedBytes;
  }

  let signature = '';
  if (SECURE_ENABLE_HMAC_SIGNING && keys) {
    const bytesForHmac = SECURE_ENABLE_BODY_ENCRYPTION
      ? encryptedBytes
      : body != null
        ? new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body))
        : null;
    const bodyHash = await computeBodyHash(bytesForHmac);
    signature = await computeSignature(method, path, query ?? '', timestamp, nonce, bodyHash, keys.hmacKey);
  }

  const encryptedKey = needKeys && keys
    ? await encryptSecretKey(keys.rawAesBytes, keys.rawHmacBytes)
    : '';

  return {
    encryptedBody: SECURE_ENABLE_BODY_ENCRYPTION
      ? encryptedBase64
      : (body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : ''),
    headers: {
      'X-Timestamp':     timestamp,
      'X-Nonce':         nonce,
      'X-Signature':     signature,
      'X-Encrypted-Key': encryptedKey,
    },
  };
}
```

#### `axiosSecureInterceptor.ts`

```ts
import axios, { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { buildSecureRequest, clearPublicKeyCache } from './secureRequestService';

const SECURED_METHODS = ['POST', 'PUT', 'PATCH'] as const;

function buildQueryString(params?: Record<string, unknown>): string {
  if (!params || Object.keys(params).length === 0) return '';
  return '?' + new URLSearchParams(params as Record<string, string>).toString();
}

export function installSecureRequestInterceptor(axiosInstance: AxiosInstance): void {

  // ── Request interceptor ────────────────────────────────────────────────────
  axiosInstance.interceptors.request.use(
    async (config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> => {
      const method = (config.method ?? 'GET').toUpperCase();
      if (!(SECURED_METHODS as readonly string[]).includes(method)) return config;

      const urlObj = new URL(config.url!, 'http://x');
      const path   = urlObj.pathname;
      const query  = buildQueryString(config.params);

      (config as any)._originalData = config.data;

      const { encryptedBody, headers } = await buildSecureRequest(method, path, query, config.data);

      config.data            = encryptedBody;
      config.transformRequest = [(data: unknown) => data]; // bypass axios serialization
      config.headers.set('Content-Type', 'text/plain; charset=utf-8');

      if (headers['X-Encrypted-Key']) config.headers.set('X-Encrypted-Key', headers['X-Encrypted-Key']);
      if (headers['X-Signature'])     config.headers.set('X-Signature',     headers['X-Signature']);
      config.headers.set('X-Timestamp', headers['X-Timestamp']);
      config.headers.set('X-Nonce',     headers['X-Nonce']);

      return config;
    }
  );

  // ── Response interceptor — auto-retry on 422 (server restart / key change) ─
  axiosInstance.interceptors.response.use(
    (response: AxiosResponse) => response,
    async (error) => {
      const config = error.config as InternalAxiosRequestConfig & { _retried?: boolean };
      const method = (config?.method ?? 'GET').toUpperCase();

      if (
        error.response?.status === 422 &&
        config && !config._retried &&
        (SECURED_METHODS as readonly string[]).includes(method)
      ) {
        config._retried = true;
        clearPublicKeyCache();

        const urlObj       = new URL(config.url!, 'http://x');
        const path         = urlObj.pathname;
        const query        = buildQueryString(config.params);
        const originalBody = (config as any)._originalData ?? null;

        const { encryptedBody, headers } = await buildSecureRequest(method, path, query, originalBody);

        config.data            = encryptedBody;
        config.transformRequest = [(data: unknown) => data];
        config.headers.set('Content-Type', 'text/plain; charset=utf-8');

        if (headers['X-Encrypted-Key']) config.headers.set('X-Encrypted-Key', headers['X-Encrypted-Key']);
        if (headers['X-Signature'])     config.headers.set('X-Signature',     headers['X-Signature']);
        config.headers.set('X-Timestamp', headers['X-Timestamp']);
        config.headers.set('X-Nonce',     headers['X-Nonce']);

        return axiosInstance(config);
      }

      return Promise.reject(error);
    }
  );
}
```

**.env files**

```env
# .env.production
REACT_APP_SECURE_BODY_ENCRYPTION=true
REACT_APP_SECURE_HMAC_SIGNING=true

# .env.development
REACT_APP_SECURE_BODY_ENCRYPTION=false
REACT_APP_SECURE_HMAC_SIGNING=false
```

---

### JavaScript (plain JS / no bundler)

```js
const API_BASE_URL    = 'https://your-api.com';
const PUBLIC_KEY_PATH = '/api/secure/public-key';

const SECURE_ENABLE_BODY_ENCRYPTION = true; // match appsettings EnableBodyEncryption
const SECURE_ENABLE_HMAC_SIGNING    = true; // match appsettings EnableHmacSigning

// ── RSA public key cache ───────────────────────────────────────────────────────
let _cachedRsaPublicKey = null;

async function getServerPublicKey() {
  if (_cachedRsaPublicKey) return _cachedRsaPublicKey;

  const response = await fetch(`${API_BASE_URL}${PUBLIC_KEY_PATH}`);
  if (!response.ok) throw new Error(`[SecureRequest] Failed to fetch public key: ${response.status}`);

  const data = await response.json();
  const publicKeyBase64 = data?.publicKey ?? data?.result ?? data;
  const publicKeyBytes  = base64ToBytes(publicKeyBase64);

  _cachedRsaPublicKey = await crypto.subtle.importKey(
    'spki', publicKeyBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false, ['encrypt']
  );
  return _cachedRsaPublicKey;
}

function clearPublicKeyCache() {
  _cachedRsaPublicKey = null;
}

// ── Byte helpers ───────────────────────────────────────────────────────────────
function base64ToBytes(base64) {
  let normalized = base64.trim().replace(/-/g, '+').replace(/_/g, '/');
  const rem = normalized.length % 4;
  if (rem) normalized += '='.repeat(4 - rem);
  return Uint8Array.from(atob(normalized), c => c.charCodeAt(0));
}

function bytesToBase64(bytes) {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ── Per-request key generation ─────────────────────────────────────────────────
async function generateRequestKeys() {
  const secret       = crypto.getRandomValues(new Uint8Array(64));
  const rawAesBytes  = secret.slice(0, 32);
  const rawHmacBytes = secret.slice(32);

  const [aesKey, hmacKey] = await Promise.all([
    crypto.subtle.importKey('raw', rawAesBytes,  { name: 'AES-GCM' },               false, ['encrypt']),
    crypto.subtle.importKey('raw', rawHmacBytes, { name: 'HMAC', hash: 'SHA-256' },  false, ['sign']),
  ]);
  return { aesKey, hmacKey, rawAesBytes, rawHmacBytes };
}

// ── AES-256-GCM body encryption ────────────────────────────────────────────────
async function encryptBody(body, aesKey) {
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  const encoded = new TextEncoder().encode(payload);

  const ciphertextWithTag = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, aesKey, encoded
  );

  const result = new Uint8Array(iv.length + ciphertextWithTag.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertextWithTag), iv.length);
  return { encryptedBytes: result, encryptedBase64: bytesToBase64(result) };
}

// ── Body hash ──────────────────────────────────────────────────────────────────
async function computeBodyHash(bytes) {
  if (!bytes || bytes.length === 0)
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

// ── HMAC signature ─────────────────────────────────────────────────────────────
async function computeSignature(method, path, query, timestamp, nonce, bodyHash, hmacKey) {
  const canonical = [method.toUpperCase(), path, query, timestamp, nonce, bodyHash].join('\n');
  const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(canonical));
  return bytesToBase64(new Uint8Array(sig));
}

// ── RSA encrypt 64-byte secret ─────────────────────────────────────────────────
async function encryptSecretKey(rawAesBytes, rawHmacBytes) {
  const combined = new Uint8Array(64);
  combined.set(rawAesBytes, 0);
  combined.set(rawHmacBytes, 32);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, await getServerPublicKey(), combined
  );
  return bytesToBase64(new Uint8Array(encrypted));
}

// ── Public API ─────────────────────────────────────────────────────────────────
async function buildSecureRequest(method, path, query, body) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomUUID();

  const needKeys = SECURE_ENABLE_BODY_ENCRYPTION || SECURE_ENABLE_HMAC_SIGNING;
  const keys     = needKeys ? await generateRequestKeys() : null;

  let encryptedBase64 = '';
  let encryptedBytes  = null;

  if (SECURE_ENABLE_BODY_ENCRYPTION && keys && body != null) {
    const result    = await encryptBody(body, keys.aesKey);
    encryptedBase64 = result.encryptedBase64;
    encryptedBytes  = result.encryptedBytes;
  }

  let signature = '';
  if (SECURE_ENABLE_HMAC_SIGNING && keys) {
    const bytesForHmac = SECURE_ENABLE_BODY_ENCRYPTION
      ? encryptedBytes
      : body != null
        ? new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body))
        : null;
    const bodyHash = await computeBodyHash(bytesForHmac);
    signature = await computeSignature(method, path, query ?? '', timestamp, nonce, bodyHash, keys.hmacKey);
  }

  const encryptedKey = needKeys && keys
    ? await encryptSecretKey(keys.rawAesBytes, keys.rawHmacBytes)
    : '';

  return {
    encryptedBody: SECURE_ENABLE_BODY_ENCRYPTION
      ? encryptedBase64
      : (body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : ''),
    headers: {
      'X-Timestamp':     timestamp,
      'X-Nonce':         nonce,
      'X-Signature':     signature,
      'X-Encrypted-Key': encryptedKey,
    },
  };
}

// ── Axios integration (optional) ───────────────────────────────────────────────
function installSecureRequestInterceptor(axiosInstance) {
  const SECURED_METHODS = ['POST', 'PUT', 'PATCH'];

  axiosInstance.interceptors.request.use(async (config) => {
    const method = (config.method ?? 'GET').toUpperCase();
    if (!SECURED_METHODS.includes(method)) return config;

    const urlObj = new URL(config.url, 'http://x');
    const path   = urlObj.pathname;
    const params = config.params ? '?' + new URLSearchParams(config.params).toString() : '';

    config._originalData = config.data;

    const { encryptedBody, headers } = await buildSecureRequest(method, path, params, config.data);

    config.data             = encryptedBody;
    config.transformRequest = [(data) => data];
    config.headers['Content-Type'] = 'text/plain; charset=utf-8';

    if (headers['X-Encrypted-Key']) config.headers['X-Encrypted-Key'] = headers['X-Encrypted-Key'];
    if (headers['X-Signature'])     config.headers['X-Signature']     = headers['X-Signature'];
    config.headers['X-Timestamp'] = headers['X-Timestamp'];
    config.headers['X-Nonce']     = headers['X-Nonce'];

    return config;
  });

  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
      const config = error.config;
      const method = (config?.method ?? 'GET').toUpperCase();

      if (error.response?.status === 422 && config && !config._retried && SECURED_METHODS.includes(method)) {
        config._retried = true;
        clearPublicKeyCache();

        const urlObj       = new URL(config.url, 'http://x');
        const path         = urlObj.pathname;
        const params       = config.params ? '?' + new URLSearchParams(config.params).toString() : '';
        const originalBody = config._originalData ?? null;

        const { encryptedBody, headers } = await buildSecureRequest(method, path, params, originalBody);

        config.data             = encryptedBody;
        config.transformRequest = [(data) => data];
        config.headers['Content-Type'] = 'text/plain; charset=utf-8';

        if (headers['X-Encrypted-Key']) config.headers['X-Encrypted-Key'] = headers['X-Encrypted-Key'];
        if (headers['X-Signature'])     config.headers['X-Signature']     = headers['X-Signature'];
        config.headers['X-Timestamp'] = headers['X-Timestamp'];
        config.headers['X-Nonce']     = headers['X-Nonce'];

        return axiosInstance(config);
      }

      return Promise.reject(error);
    }
  );
}
```

**Usage with plain `fetch`:**

```js
// One-time setup — call on app boot
await getServerPublicKey();

// On each POST/PUT/PATCH request
const { encryptedBody, headers } = await buildSecureRequest('POST', '/api/users', '', { name: 'Osama' });

const response = await fetch('https://your-api.com/api/users', {
  method: 'POST',
  headers: {
    'Content-Type':   'text/plain; charset=utf-8',
    'X-Timestamp':    headers['X-Timestamp'],
    'X-Nonce':        headers['X-Nonce'],
    'X-Signature':    headers['X-Signature'],
    'X-Encrypted-Key': headers['X-Encrypted-Key'],
  },
  body: encryptedBody,
});
```

---

## License

MIT
