# secure-request
SecureRequest — ASP.NET Core middleware that adds RSA + AES-256-GCM body encryption, HMAC-SHA256 request signing, timestamp validation, and nonce-based anti-replay protection to any API endpoint. Zero static secrets — all keys are generated per-request and exchanged via RSA.
