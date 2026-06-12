using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureRequest.Crypto;
using SecureRequest.KeyStorage;
using SecureRequest.Options;

namespace SecureRequest.Services;

/// <summary>
/// Background service that periodically reloads the RSA private key from the configured
/// <see cref="IRsaKeyStorageProvider"/> to propagate key rotations across all instances.
///
/// Problem it solves:
///   When <see cref="ISecureRequestKeyRotationService.RotateKeyAsync"/> runs on instance A,
///   instances B and C still hold the old key in memory. Clients that hit B or C after the
///   rotation receive a 422 until those instances restart or reload the key.
///
/// Solution:
///   This service wakes every <see cref="SecureRequestOptions.KeyReloadIntervalSeconds"/>
///   seconds, fetches the current key from the storage provider, and hot-swaps it into
///   the in-memory <see cref="RsaKeyProvider"/>. All instances converge to the new key
///   within one reload interval — no restart required.
///
/// Configuration:
/// <code>
/// "SecureRequest": {
///   "KeyReloadIntervalSeconds": 300   // reload every 5 minutes (default)
///                                     // set to 0 to disable (single-instance / dev)
/// }
/// </code>
/// </summary>
public sealed class RsaKeyReloaderService : BackgroundService
{
    private readonly RsaKeyProvider          _rsaKeyProvider;
    private readonly IServiceScopeFactory    _scopeFactory;
    private readonly SecureRequestOptions    _options;
    private readonly ILogger<RsaKeyReloaderService> _logger;

    /// <summary>Initializes the service with the RSA key provider, scope factory, options, and logger.</summary>
    public RsaKeyReloaderService(
        RsaKeyProvider                   rsaKeyProvider,
        IServiceScopeFactory             scopeFactory,
        IOptions<SecureRequestOptions>   options,
        ILogger<RsaKeyReloaderService>   logger)
    {
        _rsaKeyProvider = rsaKeyProvider ?? throw new ArgumentNullException(nameof(rsaKeyProvider));
        _scopeFactory   = scopeFactory   ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options        = options?.Value  ?? throw new ArgumentNullException(nameof(options));
        _logger         = logger         ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.KeyReloadIntervalSeconds <= 0)
        {
            _logger.LogDebug(
                "[SecureRequest] Key auto-reload disabled (KeyReloadIntervalSeconds=0). " +
                "Key rotation will not propagate automatically in load-balanced environments.");
            return;
        }

        _logger.LogInformation(
            "[SecureRequest] Key auto-reload active — reloading every {Interval}s.",
            _options.KeyReloadIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(
                    TimeSpan.FromSeconds(_options.KeyReloadIntervalSeconds),
                    stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break; // App is shutting down — exit cleanly.
            }

            try
            {
                await using var scope   = _scopeFactory.CreateAsyncScope();
                var storage             = scope.ServiceProvider.GetRequiredService<IRsaKeyStorageProvider>();
                var keyBytes            = await storage.LoadPrivateKeyAsync(stoppingToken);

                if (keyBytes is { Length: > 0 })
                {
                    _rsaKeyProvider.LoadFromPrivateKey(keyBytes);

                    _logger.LogDebug(
                        "[SecureRequest] RSA key hot-reloaded from {Provider}. " +
                        "Rotation propagates within {Interval}s across all instances.",
                        storage.GetType().Name, _options.KeyReloadIntervalSeconds);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                // Log but don't crash — the old key remains in use until the next reload.
                _logger.LogWarning(ex,
                    "[SecureRequest] Failed to reload RSA key from storage provider. " +
                    "Will retry in {Interval}s.",
                    _options.KeyReloadIntervalSeconds);
            }
        }
    }
}
