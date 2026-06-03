# Changelog

All notable changes to **SecureRequest** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.1.0] - 2026-06-03

### Added
- `ISecureRequestKeyRotationService` — rotate the RSA key pair at runtime without restarting the server
- `SecureRequestKeyRotationService` — default implementation of key rotation
- `MapSecureRequestKeyRotation()` — protected minimal-API endpoint to trigger key rotation
- `Cache-Control: public, max-age=86400` header on the public key endpoint
- Unit tests: `RsaKeyProviderTests`, `SecureRequestCryptoServiceTests`, `DistributedCacheKeyStorageProviderTests`, `KeyRotationTests`
- Integration tests: `SecureRequestMiddlewareTests` covering all pipeline paths
- `SecureRequestCryptoService` is now `public` (was `internal`) — can be mocked in consumer tests
- `RsaKeyProvider.GetPublicKeySpki()` and `Decrypt()` are now `public`

### Changed
- `DistributedCacheKeyStorageProvider` now logs a `Warning` on startup reminding operators to use a KMS in production
- `DistributedCacheKeyStorageProvider` requires `ILogger<DistributedCacheKeyStorageProvider>` (injected via DI automatically)

### Fixed
- RSA key storage warning — the default provider now clearly communicates its security trade-offs

---

## [1.0.0] - 2026-06-03

### Added
- `IRsaKeyStorageProvider` — pluggable key storage abstraction
- `DistributedCacheKeyStorageProvider` — default implementation using `IDistributedCache`
- `SecureRequestBuilder` with fluent `.WithKeyStorage<T>()` and `.WithKeyStorage(factory)` methods
- Full KMS integration examples in README: Azure Key Vault, AWS Secrets Manager, GCP Secret Manager

### Changed
- `AddSecureRequest()` now returns `SecureRequestBuilder` for fluent chaining
- `RsaKeyInitializerService` now resolves `IRsaKeyStorageProvider` instead of `IDistributedCache` directly

---

## [1.0.0] - 2026-06-03

### Added
- `SecureRequestMiddleware` — full secure-request pipeline for ASP.NET Core
- RSA-2048 + AES-256-GCM body encryption
- HMAC-SHA256 request signing
- Timestamp validation (configurable tolerance)
- Nonce-based anti-replay protection via `IDistributedCache`
- `SecureRequestOptions` with `Enabled`, `EnableBodyEncryption`, `EnableHmacSigning`, `SecuredMethods`, `ExcludedPaths`
- `AddSecureRequest()`, `UseSecureRequest()`, `MapSecureRequestPublicKey()` extension methods
- `RsaKeyInitializerService` — Redis-backed RSA key persistence for load-balanced environments
- TypeScript and JavaScript frontend integration samples
