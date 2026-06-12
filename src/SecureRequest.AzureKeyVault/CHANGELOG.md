# Changelog — SecureRequest.AzureKeyVault

All notable changes to this package are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] — 2026-06-12

### Added
- **True HSM mode** — `WithAzureKeyVaultHsm(keyVaultUri, keyName)` extension method.
  The RSA key pair lives entirely inside Azure Key Vault; the private key never enters app memory.
- `AzureKeyVaultDecryptProvider` — `IRsaDecryptProvider` that sends ciphertext to
  `CryptographyClient.DecryptAsync(RsaOaep256, ...)` for in-vault decryption.
- `AzureKeyVaultHsmInitializerService` — `IHostedService` that fetches the RSA public key
  from Key Vault at startup and loads it via `RsaKeyProvider.LoadPublicKeyOnly()`.
- Dependency on `Azure.Security.KeyVault.Keys` 4.6.0.

### Changed
- Core dependency bumped to `SecureRequest` 1.2.0 (required for `IRsaDecryptProvider`,
  `RsaKeyProvider.LoadPublicKeyOnly()`, and `MemoryKeyStorageProvider`).
- README updated to document both Secrets mode and True HSM mode with code examples
  and a comparison table.

---

## [1.0.0] — 2026-06-10

### Added
- Initial release.
- `AzureKeyVaultKeyStorageProvider` — stores RSA private key as an Azure Key Vault secret.
- `WithAzureKeyVault(keyVaultUri, secretName?, credential?)` extension on `SecureRequestBuilder`.
- `DefaultAzureCredential` used by default (supports Managed Identity, Azure CLI, Visual Studio).
