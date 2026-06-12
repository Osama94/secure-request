using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;

namespace SecureRequest.AzureKeyVault;

/// <summary>
/// <see cref="IRsaDecryptProvider"/> that performs RSA-OAEP-SHA256 decryption entirely
/// inside Azure Key Vault — the RSA private key <b>never leaves the HSM</b>.
///
/// How it works:
/// <list type="number">
///   <item>The client encrypts the 64-byte secret using the server's RSA public key
///         (fetched from <c>/api/secure/public-key</c>).</item>
///   <item>The middleware sends the ciphertext to Key Vault's <c>Decrypt</c> API.</item>
///   <item>Key Vault returns only the plaintext — the private key never exits the vault.</item>
/// </list>
///
/// Register via:
/// <code>
/// builder.Services
///     .AddSecureRequest(builder.Configuration)
///     .WithAzureKeyVaultHsm(
///         keyVaultUri : "https://your-vault.vault.azure.net/",
///         keyName     : "secure-request-rsa-key");
/// </code>
/// </summary>
public sealed class AzureKeyVaultDecryptProvider : IRsaDecryptProvider
{
    private readonly CryptographyClient                  _cryptoClient;
    private readonly ILogger<AzureKeyVaultDecryptProvider> _logger;

    /// <summary>
    /// Initializes the provider with an authenticated <see cref="CryptographyClient"/>
    /// scoped to the specific Key Vault key.
    /// </summary>
    public AzureKeyVaultDecryptProvider(
        CryptographyClient                  cryptoClient,
        ILogger<AzureKeyVaultDecryptProvider> logger)
    {
        _cryptoClient = cryptoClient ?? throw new ArgumentNullException(nameof(cryptoClient));
        _logger       = logger       ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Sends the ciphertext to Azure Key Vault and receives the plaintext.
    /// The RSA private key never leaves the HSM.
    /// Adds a network round-trip per request compared to <see cref="LocalRsaDecryptProvider"/>.
    /// </remarks>
    public async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug(
            "[SecureRequest.AzureKeyVault] Decrypting via Key Vault HSM " +
            "(private key never leaves the vault).");

        var result = await _cryptoClient.DecryptAsync(
            EncryptionAlgorithm.RsaOaep256,
            ciphertext,
            cancellationToken);

        _logger.LogDebug(
            "[SecureRequest.AzureKeyVault] Key Vault decrypt completed.");

        return result.Plaintext;
    }
}
