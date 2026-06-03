using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;

namespace SecureRequest.Services;

/// <summary>
/// Hosted service that initialises the RSA key pair exactly once at application startup.
///
/// Strategy:
///   1. Look up the private key in the distributed cache (Redis / memory / SQL).
///   2. Found   → load it — all instances share the same key pair.
///   3. Not found → generate a new key pair, persist it to the cache (effectively permanent TTL).
///
/// This guarantees all server instances behind a load balancer always decrypt
/// X-Encrypted-Key headers correctly regardless of which instance handles the request.
/// </summary>
public sealed class RsaKeyInitializerService : IHostedService
{
    private const string CacheKey    = "secure_request:rsa_private_key";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromDays(365 * 10); // ~10 years

    private readonly RsaKeyProvider              _rsaKeyProvider;
    private readonly IServiceScopeFactory        _scopeFactory;
    private readonly ILogger<RsaKeyInitializerService> _logger;

    public RsaKeyInitializerService(
        RsaKeyProvider rsaKeyProvider,
        IServiceScopeFactory scopeFactory,
        ILogger<RsaKeyInitializerService> logger)
    {
        _rsaKeyProvider = rsaKeyProvider;
        _scopeFactory   = scopeFactory;
        _logger         = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // IDistributedCache may be scoped/transient in some providers — resolve via scope.
        await using var scope = _scopeFactory.CreateAsyncScope();
        var cache = scope.ServiceProvider.GetRequiredService<IDistributedCache>();

        var existingKeyBase64 = await cache.GetStringAsync(CacheKey, cancellationToken);

        if (!string.IsNullOrWhiteSpace(existingKeyBase64))
        {
            _logger.LogInformation(
                "[SecureRequest] RSA key pair loaded from distributed cache. " +
                "All instances share the same key pair.");

            var privateKeyBytes = Convert.FromBase64String(existingKeyBase64);
            _rsaKeyProvider.LoadFromPrivateKey(privateKeyBytes);
        }
        else
        {
            _logger.LogInformation(
                "[SecureRequest] No RSA key found in cache. Generating a new 2048-bit key pair.");

            var privateKeyBytes  = _rsaKeyProvider.GenerateAndExportPrivateKey();
            var privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);

            await cache.SetStringAsync(
                CacheKey,
                privateKeyBase64,
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = CacheTtl },
                cancellationToken);

            _logger.LogInformation(
                "[SecureRequest] RSA key pair generated and persisted to distributed cache.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
