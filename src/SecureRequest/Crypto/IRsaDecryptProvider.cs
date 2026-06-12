namespace SecureRequest.Crypto;

/// <summary>
/// Performs the RSA-OAEP-SHA256 decryption of the per-request secret key.
///
/// The default implementation (<see cref="LocalRsaDecryptProvider"/>) decrypts
/// locally using the in-memory <see cref="RsaKeyProvider"/>.
///
/// Replace this with a cloud KMS implementation (e.g. <c>AzureKeyVaultDecryptProvider</c>
/// from the <c>SecureRequest.AzureKeyVault</c> package) to achieve true zero-export HSM
/// where the RSA private key never leaves the hardware security module.
///
/// Register a custom provider via the fluent builder:
/// <code>
/// builder.Services
///     .AddSecureRequest(builder.Configuration)
///     .WithDecryptProvider&lt;MyHsmDecryptProvider&gt;();
/// </code>
/// </summary>
public interface IRsaDecryptProvider
{
    /// <summary>
    /// Decrypts the RSA-OAEP-SHA256 <paramref name="ciphertext"/> and returns the 64-byte
    /// plaintext secret (bytes 0–31 = AES-256 key, bytes 32–63 = HMAC-SHA256 key).
    ///
    /// Implementations that delegate to a remote KMS must be async — the middleware
    /// always calls this method asynchronously.
    /// </summary>
    Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
}
