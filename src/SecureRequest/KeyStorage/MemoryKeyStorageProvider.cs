namespace SecureRequest.KeyStorage;

/// <summary>
/// In-memory <see cref="IRsaKeyStorageProvider"/> that stores the RSA private key
/// in process memory only — no external persistence.
///
/// Use cases:
/// <list type="bullet">
///   <item>Local development — no Redis required to start the app.</item>
///   <item>Single-instance deployments where key sharing is not needed.</item>
///   <item>HSM mode — when the real RSA key pair lives in a cloud KMS (e.g. Azure Key Vault Keys)
///         and the local process never holds the private key at all.</item>
/// </list>
///
/// ⚠️ Not suitable for load-balanced production deployments unless paired with a
/// cloud KMS decrypt provider: each instance generates its own key pair and clients
/// can only decrypt on the same instance that issued the public key.
///
/// Register via the fluent builder:
/// <code>
/// builder.Services
///     .AddSecureRequest(builder.Configuration)
///     .WithMemoryStorage();
/// </code>
/// </summary>
public sealed class MemoryKeyStorageProvider : IRsaKeyStorageProvider
{
    private byte[]? _privateKey;

    /// <inheritdoc/>
    public Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_privateKey);

    /// <inheritdoc/>
    public Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default)
    {
        _privateKey = privateKeyBytes;
        return Task.CompletedTask;
    }
}
