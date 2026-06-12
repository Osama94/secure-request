# SecureRequest.AwsSecretsManager

AWS Secrets Manager provider for the [SecureRequest](https://www.nuget.org/packages/SecureRequest) NuGet package.

Stores the RSA private key inside **AWS Secrets Manager** instead of Redis/`IDistributedCache`,
protected by IAM access control, CloudTrail audit logging, and KMS encryption at rest.

---

## Installation

```bash
dotnet add package SecureRequest
dotnet add package SecureRequest.AwsSecretsManager
```

---

## Usage

Chain `.WithAwsSecretsManager()` onto `AddSecureRequest()`:

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAwsSecretsManager(); // uses default AWS credential chain (IAM role, env vars, ~/.aws)
```

The AWS SDK default credential chain is used automatically — picks up IAM roles (EC2/ECS/Lambda/EKS), environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), and `~/.aws/credentials` in development.

---

## Custom secret ID and region

```csharp
builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAwsSecretsManager(
        secretId : "myapp/prod/rsa-key",
        region   : RegionEndpoint.EUWest1);
```

---

## Bring your own client (already in DI)

```csharp
// Register with custom credentials
builder.Services.AddSingleton<IAmazonSecretsManager>(
    new AmazonSecretsManagerClient(new StoredProfileAWSCredentials("my-profile")));

builder.Services
    .AddSecureRequest(builder.Configuration)
    .WithAwsSecretsManager(
        clientFactory: sp => sp.GetRequiredService<IAmazonSecretsManager>());
```

---

## Required IAM permissions

The IAM role or user running the application needs the following policy:

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue"
  ],
  "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:secure-request/rsa-private-key*"
}
```

On first startup the provider creates the secret (`CreateSecret`).
On every subsequent startup it reads it back (`GetSecretValue`).
On key rotation it updates the value (`PutSecretValue`).

---

## appsettings.json

No changes needed — `SecureRequest` options are still bound from the same section:

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
> Only the RSA private key moves to Secrets Manager — nonces remain in Redis/in-memory cache.

---

## Comparison

| | Default (Redis) | `AwsSecretsManagerKeyStorageProvider` |
|---|---|---|
| Key stored in | Redis (plain Base64) | AWS Secrets Manager (KMS-encrypted) |
| Access control | Redis connection string | IAM roles and policies |
| Audit trail | None | AWS CloudTrail |
| Encryption at rest | Depends on Redis config | AES-256 via AWS KMS (automatic) |
| Compliance | Not sufficient for PCI-DSS / HIPAA | Satisfies requirements |

---

## License

MIT
