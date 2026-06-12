# Changelog

All notable changes to **SecureRequest** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-06-12

### Added
- `IRsaDecryptProvider` — abstraction for RSA-OAEP decryption. Default: `LocalRsaDecryptProvider` (in-process). Override with a cloud HSM provider for true zero-export key protection.
- `LocalRsaDecryptProvider` — default implementation wrapping `RsaKeyProvider`. No behaviour change for existing consumers.
- `MemoryKeyStorageProvider` — in-memory key storage, no Redis required. For dev and single-instance deployments. Register via `.WithMemoryStorage()`.
- `RsaKeyReloaderService` — background service that hot-reloads the RSA key every `KeyReloadIntervalSeconds`. Fixes the distributed rotation bug: all instances converge to the new key within the configured window without restarting.
- `KeyReloadIntervalSeconds` option (default: 300 s, set to 0 to disable).
- `ISecureRequestCryptoService.DecryptSecretKeyAsync` — async overload with default impl. `SecureRequestCryptoService` overrides it to route through `IRsaDecryptProvider`, enabling async cloud KMS calls.
- `SecureRequestBuilder.WithDecryptProvider<T>()` and `WithDecryptProvider(factory)`.
- `SecureRequestBuilder.WithMemoryStorage()`.
- `SecureRequestBuilder.RemoveHostedService<T>()` — for companion packages replacing built-in hosted services.
- `SecureRequestBuilder.Services` — exposes `IServiceCollection` for advanced companion scenarios.
- `RsaKeyProvider.LoadPublicKeyOnly(byte[])` — loads a public-key-only RSA object from SPKI bytes. Used by cloud HSM providers where the private key never leaves the KMS.

### Changed
- `SecureRequestMiddleware` now calls `DecryptSecretKeyAsync` (async HSM path) instead of `DecryptSecretKey`.
- `SecureRequestCryptoService` now injects `IRsaDecryptProvider` alongside `RsaKeyProvider`.

### Fixed
- **Distributed rotation bug** — other instances now hot-reload the new key via `RsaKeyReloaderService` without restarting.
- **Redis required in dev** — `MemoryKeyStorageProvider` removes this requirement.

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

