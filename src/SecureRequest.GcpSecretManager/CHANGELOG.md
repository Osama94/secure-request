# Changelog — SecureRequest.GcpSecretManager

All notable changes to this package are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-06-12

### Added
- Initial release.
- `GcpSecretManagerKeyStorageProvider` — stores RSA private key as a Base64 secret version in GCP Secret Manager.
- `WithGcpSecretManager(projectId, secretId?, clientFactory?)` extension on `SecureRequestBuilder`.
- Auto-creates the secret with Automatic replication on first startup; adds a new version on rotation.
- gRPC `StatusCode.NotFound` handling for clean first-startup experience.
- Compatible with `SecureRequest` 1.2.0+.
