using Azure;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using SecureRequest.KeyStorage;

namespace SecureRequest.AzureKeyVault;

/// <summary>
/// <see cref="IRsaKeyStorageProvider"/> implementation that stores the RSA private key
/// as a Base64-encoded secret inside Azure Key Vault.
///
/// The private key is stored as a Base64 string under <see cref="DefaultSecretName"/> by default.
/// Azure Key Vault handles encryption at rest, access control (RBAC / access policies),
/// audit logging, and optional HSM-backed storage (Key Vault Premium tier).
///
/// The key <b>does</b> travel over TLS to the application when loaded — for zero-export
/// guarantees, use Azure Key Vault <i>Keys</i> with RSA-unwrap operations instead.
/// This provider is sufficient for the vast majority of production workloads.
/// </summary>
public sealed class AzureKeyVaultKeyStorageProvider : IRsaKeyStorageProvider
{
    private readonly SecretClient _client;
    private readonly string _secretName;
    private readonly ILogger<AzureKeyVaultKeyStorageProvider> _logger;

    /// <summary>Default secret name used when none is specified.</summary>
    public const string DefaultSecretName = "SecureRequest-RsaPrivateKey";

    /// <summary>
    /// Initializes a new instance of <see cref="AzureKeyVaultKeyStorageProvider"/>.
    /// </summary>
    /// <param name="client">An authenticated <see cref="SecretClient"/> for your Key Vault.</param>
    /// <param name="secretName">Name of the secret that holds the RSA private key.</param>
    /// <param name="logger">Logger injected by DI.</param>
    public AzureKeyVaultKeyStorageProvider(
        SecretClient                              client,
        string                                   secretName,
        ILogger<AzureKeyVaultKeyStorageProvider> logger)
    {
        _client     = client     ?? throw new ArgumentNullException(nameof(client));
        _secretName = secretName ?? throw new ArgumentNullException(nameof(secretName));
        _logger     = logger     ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug(
                "[SecureRequest.AzureKeyVault] Loading RSA private key from Key Vault secret '{SecretName}'.",
                _secretName);

            var response = await _client.GetSecretAsync(_secretName, cancellationToken: cancellationToken);
            var bytes    = Convert.FromBase64String(response.Value.Value);

            _logger.LogInformation(
                "[SecureRequest.AzureKeyVault] RSA private key loaded from Key Vault secret '{SecretName}'.",
                _secretName);

            return bytes;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogInformation(
                "[SecureRequest.AzureKeyVault] Secret '{SecretName}' not found — a new RSA key pair will be generated.",
                _secretName);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.AzureKeyVault] Failed to load RSA private key from Key Vault secret '{SecretName}'.",
                _secretName);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default)
    {
        try
        {
            var base64 = Convert.ToBase64String(privateKeyBytes);

            await _client.SetSecretAsync(_secretName, base64, cancellationToken);

            _logger.LogInformation(
                "[SecureRequest.AzureKeyVault] RSA private key stored in Key Vault secret '{SecretName}'.",
                _secretName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.AzureKeyVault] Failed to store RSA private key in Key Vault secret '{SecretName}'.",
                _secretName);
            throw;
        }
    }
}
