# Changelog — SecureRequest.AwsSecretsManager

All notable changes to this package are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-06-12

### Added
- Initial release (replaces the incorrectly named `SecureRequest.AwsKms` package).
- `AwsSecretsManagerKeyStorageProvider` — stores RSA private key as a Base64 secret in AWS Secrets Manager.
- `WithAwsSecretsManager(secretId?, region?, clientFactory?)` extension on `SecureRequestBuilder`.
- Auto-creates the secret on first startup; updates it on rotation via `PutSecretValue`.
- Compatible with `SecureRequest` 1.2.0+.
