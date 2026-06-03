using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace SecureRequest.KeyStorage;

/// <summary>
/// Default <see cref="IRsaKeyStorageProvider"/> implementation that persists the RSA private key
/// in <c>IDistributedCache</c> (Redis, SQL, in-memory, etc.).
///
/// ⚠️  SECURITY WARNING:
/// This provider stores the RSA private key as plain Base64 in your distributed cache.
/// Anyone with read access to Redis / your cache store can extract the private key and
/// decrypt all X-Encrypted-Key headers, defeating the purpose of the encryption.
///
/// For production systems handling sensitive data, replace this with a dedicated
/// Key Management Service using <c>.WithKeyStorage&lt;YourProvider&gt;()</c>:
///   - Azure Key Vault  → <c>AzureKeyVaultStorageProvider</c>
///   - AWS KMS / Secrets Manager → <c>AwsSecretsManagerStorageProvider</c>
///   - Google Cloud Secret Manager → <c>GcpSecretManagerStorageProvider</c>
///   - HashiCorp Vault → custom <c>IRsaKeyStorageProvider</c> implementation
///
/// This default implementation is intentionally kept simple for development and
/// low-sensitivity environments where the cache store is already trusted.
/// </summary>
public sealed class DistributedCacheKeyStorageProvider : IRsaKeyStorageProvider
{
    private const string CacheKey = "secure_request:rsa_private_key";
    private static readonly TimeSpan Ttl = TimeSpan.FromDays(365 * 10); // ~10 years

    private readonly IDistributedCache _cache;
    private readonly ILogger<DistributedCacheKeyStorageProvider> _logger;

    /// <summary>Initializes the provider with the distributed cache and logger.</summary>
    public DistributedCacheKeyStorageProvider(
        IDistributedCache cache,
        ILogger<DistributedCacheKeyStorageProvider> logger)
    {
        _cache  = cache;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogWarning(
            "[SecureRequest] Using DistributedCacheKeyStorageProvider — RSA private key is stored " +
            "as plain Base64 in the cache. For production, replace with a KMS-backed provider via " +
            ".WithKeyStorage<T>() (Azure Key Vault, AWS KMS, GCP Secret Manager, etc.).");

        var base64 = await _cache.GetStringAsync(CacheKey, cancellationToken);
        return string.IsNullOrWhiteSpace(base64) ? null : Convert.FromBase64String(base64);
    }

    /// <inheritdoc/>
    public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default)
    {
        await _cache.SetStringAsync(
            CacheKey,
            Convert.ToBase64String(privateKeyBytes),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = Ttl },
            cancellationToken);
    }
}
