using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;
using SecureRequest.KeyStorage;

namespace SecureRequest.Services;

/// <summary>
/// Default implementation of <see cref="ISecureRequestKeyRotationService"/>.
/// </summary>
public sealed class SecureRequestKeyRotationService : ISecureRequestKeyRotationService
{
    private readonly RsaKeyProvider              _rsaKeyProvider;
    private readonly IRsaKeyStorageProvider      _storageProvider;
    private readonly ILogger<SecureRequestKeyRotationService> _logger;

    /// <summary>Initializes the rotation service with the RSA key provider, storage provider, and logger.</summary>
    public SecureRequestKeyRotationService(
        RsaKeyProvider rsaKeyProvider,
        IRsaKeyStorageProvider storageProvider,
        ILogger<SecureRequestKeyRotationService> logger)
    {
        _rsaKeyProvider  = rsaKeyProvider;
        _storageProvider = storageProvider;
        _logger          = logger;
    }

    /// <inheritdoc/>
    public async Task<string> RotateKeyAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogWarning(
            "[SecureRequest] RSA key rotation initiated via {Provider}.",
            _storageProvider.GetType().Name);

        // 1. Generate new key pair and activate it in memory immediately
        var newPrivateKeyBytes = _rsaKeyProvider.GenerateAndExportPrivateKey();

        // 2. Persist the new private key — overwrites the old one in the store
        await _storageProvider.StorePrivateKeyAsync(newPrivateKeyBytes, cancellationToken);

        var newPublicKeyBase64 = _rsaKeyProvider.GetPublicKeyBase64();

        _logger.LogWarning(
            "[SecureRequest] RSA key rotation complete. New public key (first 32 chars): {KeyPreview}...",
            newPublicKeyBase64[..Math.Min(32, newPublicKeyBase64.Length)]);

        // Clients holding the old public key will get 422 on their next secured request.
        // The built-in frontend 422 auto-retry handles this transparently:
        //   clear cached public key → re-fetch new key → re-encrypt → retry.

        return newPublicKeyBase64;
    }
}
