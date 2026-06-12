using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;
using SecureRequest.KeyStorage;

namespace SecureRequest.Services;

/// <summary>
/// Hosted service that initialises the RSA key pair exactly once at application startup.
///
/// Strategy:
///   1. Resolve <see cref="IRsaKeyStorageProvider"/> — defaults to distributed cache,
///      or a custom KMS provider registered via <c>.WithKeyStorage&lt;T&gt;()</c>.
///   2. Found   → load it — all instances share the same key pair.
///   3. Not found → generate a new key pair, persist it via the storage provider.
///
/// This guarantees all server instances behind a load balancer always decrypt
/// X-Encrypted-Key headers correctly regardless of which instance handles the request.
/// </summary>
public sealed class RsaKeyInitializerService : IHostedService
{
    private readonly RsaKeyProvider          _rsaKeyProvider;
    private readonly IServiceScopeFactory    _scopeFactory;
    private readonly ILogger<RsaKeyInitializerService> _logger;

    /// <summary>Initializes the service with the RSA key provider, scope factory, and logger.</summary>
    public RsaKeyInitializerService(
        RsaKeyProvider rsaKeyProvider,
        IServiceScopeFactory scopeFactory,
        ILogger<RsaKeyInitializerService> logger)
    {
        _rsaKeyProvider = rsaKeyProvider;
        _scopeFactory   = scopeFactory;
        _logger         = logger;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var storage = scope.ServiceProvider.GetRequiredService<IRsaKeyStorageProvider>();

        var privateKeyBytes = await storage.LoadPrivateKeyAsync(cancellationToken);

        if (privateKeyBytes is { Length: > 0 })
        {
            _logger.LogInformation(
                "[SecureRequest] RSA key pair loaded from {Provider}. All instances share the same key pair.",
                storage.GetType().Name);

            _rsaKeyProvider.LoadFromPrivateKey(privateKeyBytes);
        }
        else
        {
            _logger.LogInformation(
                "[SecureRequest] No RSA key found in {Provider}. Generating a new 2048-bit key pair.",
                storage.GetType().Name);

            var newPrivateKeyBytes = _rsaKeyProvider.GenerateAndExportPrivateKey();

            await storage.StorePrivateKeyAsync(newPrivateKeyBytes, cancellationToken);

            _logger.LogInformation(
                "[SecureRequest] RSA key pair generated and persisted via {Provider}.",
                storage.GetType().Name);
        }
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
