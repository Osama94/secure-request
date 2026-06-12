# SecureRequest.GcpSecretManager

Google Cloud Secret Manager provider for the [SecureRequest](https://www.nuget.org/packages/SecureRequest) NuGet package.

Stores the RSA private key inside **GCP Secret Manager** instead of Redis/`IDistributedCache`,
protected by IAM access control, Cloud Audit Logs, and optional CMEK encryption.

---

## Installation

```bash
dotnet add package SecureRequest
dotnet add package SecureRequest.GcpSecretManager
```

---

## Usage

Chain `.WithGcpSecretManager()` onto `AddSecureRequest()`:

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithGcpSecretManager(projectId: "my-gcp-project");
```

**Application Default Credentials (ADC)** are used automatically — picks up Workload Identity in GKE, `GOOGLE_APPLICATION_CREDENTIALS` environment variable, and `gcloud auth application-default login` in development.

---

## Custom secret ID

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithGcpSecretManager(
        projectId : "my-gcp-project",
        secretId  : "myapp-rsa-private-key");
```

---

## Bring your own client (already in DI)

```csharp
builder.Services.AddSingleton(SecretManagerServiceClient.Create());

builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithGcpSecretManager(
        projectId     : "my-gcp-project",
        clientFactory : sp => sp.GetRequiredService<SecretManagerServiceClient>());
```

---

## Required IAM permissions

Grant the service account running the application the following roles on the secret resource:

| Role | Purpose |
|------|---------|
| `roles/secretmanager.secretAccessor` | Read secret versions (`AccessSecretVersion`) |
| `roles/secretmanager.secretVersionAdder` | Add new versions (`AddSecretVersion`) |
| `roles/secretmanager.admin` | Create secret on first startup (`CreateSecret`) — can be reduced to `secretVersionAdder` after first run |

Minimum policy (after secret is created):
```
roles/secretmanager.secretAccessor
roles/secretmanager.secretVersionAdder
```

---

## How it works

- **First startup** — if the secret doesn't exist, `GcpSecretManagerKeyStorageProvider` creates it (Automatic replication policy) and adds the first version.
- **Subsequent startups** — reads the `latest` version to load the private key.
- **Key rotation** — adds a new version. Previous versions remain accessible (useful for auditing) but `latest` points to the new key.

---

## appsettings.json

No changes needed — `SecureRequest` options are bound from the same section:

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

> **Note:** `IDistributedCache` is still required for nonce anti-replay storage.
> Only the RSA private key moves to Secret Manager — nonces remain in Redis/in-memory cache.

---

## Comparison

| | Default (Redis) | `GcpSecretManagerKeyStorageProvider` |
|---|---|---|
| Key stored in | Redis (plain Base64) | GCP Secret Manager (AES-256 encrypted) |
| Access control | Redis connection string | IAM roles |
| Audit trail | None | Cloud Audit Logs |
| Encryption at rest | Depends on Redis config | AES-256 (optional CMEK) |
| Compliance | Not sufficient for PCI-DSS / HIPAA | Satisfies requirements |

---

## License

MIT
