# SecureRequest.AzureKeyVault

Azure Key Vault integration for the [SecureRequest](https://www.nuget.org/packages/SecureRequest) NuGet package.

Two modes are available — choose based on your security requirements:

| Mode | Private key in memory? | Decryption | When to use |
|------|------------------------|------------|-------------|
| **Secrets** (`.WithAzureKeyVault`) | ✅ Yes (loaded at startup) | In-process | Centralised key storage, audit logging |
| **True HSM** (`.WithAzureKeyVaultHsm`) | ❌ Never | Azure Key Vault | PCI-DSS, HIPAA, FIPS 140-2/3, zero-export |

---

## Installation

```bash
dotnet add package SecureRequest
dotnet add package SecureRequest.AzureKeyVault
```

---

## Mode 1 — Secrets (private key stored as a Key Vault secret)

The RSA private key is generated locally, stored as an Azure Key Vault **secret**, and loaded into memory at startup. Key Vault provides encrypted-at-rest storage, RBAC access control, and full audit logging.

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAzureKeyVault("https://your-vault.vault.azure.net/");
```

`DefaultAzureCredential` is used automatically — works with Managed Identity in Azure, and falls back to Azure CLI / Visual Studio / environment variables in development.

### Custom secret name and credential

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAzureKeyVault(
        keyVaultUri : "https://your-vault.vault.azure.net/",
        secretName  : "MyApp-RsaPrivateKey",
        credential  : new ClientSecretCredential(tenantId, clientId, clientSecret));
```

### Required permissions (Secrets mode)

| Operation | Azure RBAC role |
|-----------|----------------|
| Read secret | Key Vault Secrets User |
| Write secret | Key Vault Secrets Officer |

---

## Mode 2 — True HSM (private key never leaves Key Vault)

The RSA key pair lives **entirely inside Azure Key Vault** (or a Managed HSM). The private key never enters application memory. Decryption is delegated to Key Vault's `Decrypt` API — one Key Vault call per secured request.

### Prerequisites

1. Create an **RSA key** (type: RSA or RSA-HSM) in Key Vault with the `decrypt` operation enabled.
2. Assign the identity running the app the following RBAC roles:
   - `Key Vault Crypto User` — allows `GetKey` and `Decrypt`
   - (Optional) `Key Vault Crypto Service Encryption User` — for audit compliance

### Registration

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAzureKeyVaultHsm(
        keyVaultUri : "https://your-vault.vault.azure.net/",
        keyName     : "secure-request-rsa-key");
```

In production, prefer `ManagedIdentityCredential` for a smaller, faster credential chain:

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAzureKeyVaultHsm(
        keyVaultUri : "https://your-vault.vault.azure.net/",
        keyName     : "secure-request-rsa-key",
        credential  : new ManagedIdentityCredential());
```

### How it works

1. **Startup** — `AzureKeyVaultHsmInitializerService` calls `KeyClient.GetKeyAsync()`, extracts the public key from the JSON Web Key (`N` + `E`), and loads it into `RsaKeyProvider.LoadPublicKeyOnly()`. The `/api/secure/public-key` endpoint returns this key.
2. **Per request** — `AzureKeyVaultDecryptProvider` sends the encrypted AES secret to `CryptographyClient.DecryptAsync(RsaOaep256, ...)` and receives the plaintext. The private key never exits Key Vault.
3. **No local storage** — `MemoryKeyStorageProvider` is used automatically; no Redis or Key Vault secret is needed for key storage.

> **Note:** `IDistributedCache` is still required for nonce anti-replay storage.
> Only the decryption path moves to Key Vault — nonces remain in Redis/in-memory cache.

---

## appsettings.json

No additional configuration needed — `SecureRequest` options are bound from the same section:

```json
"SecureRequest": {
  "Enabled": true,
  "EnableBodyEncryption": true,
  "EnableHmacSigning": true,
  "TimestampToleranceSeconds": 300,
  "NonceCacheTtlSeconds": 700,
  "SecuredMethods": ["POST", "PUT", "PATCH"],
  "ExcludedPaths": []
}
```

---

## Comparison

| | Default (Redis) | Secrets mode | True HSM mode |
|---|---|---|---|
| Key stored in | Redis (Base64) | Key Vault (encrypted) | Key Vault HSM (non-exportable) |
| Private key in memory | ✅ | ✅ | ❌ |
| Access control | Redis auth | Azure RBAC | Azure RBAC |
| Audit trail | None | Key Vault logs | Key Vault logs |
| FIPS 140-2/3 compliant | No | No | Yes (RSA-HSM key type) |
| Latency per request | Negligible | Negligible | +1 Key Vault API call |

---

## License

MIT
