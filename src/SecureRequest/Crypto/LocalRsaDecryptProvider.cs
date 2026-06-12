namespace SecureRequest.Crypto;

/// <summary>
/// Default <see cref="IRsaDecryptProvider"/> that decrypts locally using the
/// in-memory <see cref="RsaKeyProvider"/>.
///
/// The RSA private key is held in process memory and is loaded from the configured
/// <see cref="KeyStorage.IRsaKeyStorageProvider"/> at startup. This is the zero-configuration
/// path — no cloud SDK required.
///
/// For true HSM (private key never leaves a hardware security module), replace this
/// with a cloud provider such as <c>AzureKeyVaultDecryptProvider</c>.
/// </summary>
public sealed class LocalRsaDecryptProvider : IRsaDecryptProvider
{
    private readonly RsaKeyProvider _keyProvider;

    /// <summary>Initializes the provider with the singleton <see cref="RsaKeyProvider"/>.</summary>
    public LocalRsaDecryptProvider(RsaKeyProvider keyProvider)
        => _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));

    /// <inheritdoc/>
    /// <remarks>
    /// Performs synchronous RSA-OAEP-SHA256 decryption in the current process.
    /// The result is wrapped in a completed task — no I/O is involved.
    /// </remarks>
    public Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
        => Task.FromResult(_keyProvider.Decrypt(ciphertext));
}
