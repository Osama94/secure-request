using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;
using System.Security.Cryptography;

namespace SecureRequest.AzureKeyVault;

/// <summary>
/// Hosted service that loads the RSA public key from an Azure Key Vault RSA key at startup.
///
/// This replaces <c>RsaKeyInitializerService</c> in HSM mode — instead of generating or
/// loading a local private key, it fetches only the public key from Key Vault and loads it
/// into <see cref="RsaKeyProvider"/> via <see cref="RsaKeyProvider.LoadPublicKeyOnly"/>.
///
/// The result: <c>GET /api/secure/public-key</c> returns the correct Key Vault public key,
/// clients can encrypt their requests against it, and decryption is performed in Key Vault
/// via <see cref="AzureKeyVaultDecryptProvider"/> — the private key never enters the app.
/// </summary>
public sealed class AzureKeyVaultHsmInitializerService : IHostedService
{
    private readonly RsaKeyProvider                          _rsaKeyProvider;
    private readonly KeyClient                               _keyClient;
    private readonly string                                  _keyName;
    private readonly ILogger<AzureKeyVaultHsmInitializerService> _logger;

    /// <summary>
    /// Initializes the service.
    /// </summary>
    /// <param name="rsaKeyProvider">Singleton that holds the in-memory RSA state.</param>
    /// <param name="keyClient">Authenticated <see cref="KeyClient"/> for the Key Vault.</param>
    /// <param name="keyName">Name of the RSA key in Key Vault.</param>
    /// <param name="logger">Logger.</param>
    public AzureKeyVaultHsmInitializerService(
        RsaKeyProvider                          rsaKeyProvider,
        KeyClient                               keyClient,
        string                                  keyName,
        ILogger<AzureKeyVaultHsmInitializerService> logger)
    {
        _rsaKeyProvider = rsaKeyProvider ?? throw new ArgumentNullException(nameof(rsaKeyProvider));
        _keyClient      = keyClient      ?? throw new ArgumentNullException(nameof(keyClient));
        _keyName        = keyName        ?? throw new ArgumentNullException(nameof(keyName));
        _logger         = logger         ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "[SecureRequest.AzureKeyVault] HSM mode — loading public key from Key Vault key '{KeyName}'.",
            _keyName);

        var response = await _keyClient.GetKeyAsync(_keyName, cancellationToken: cancellationToken);
        var jwk      = response.Value.Key;

        // Build RSA from the JSON Web Key's public components (N and E only — no private key).
        var rsaParams = new RSAParameters
        {
            Modulus  = jwk.N,
            Exponent = jwk.E
        };

        using var rsa = RSA.Create(rsaParams);
        var spki = rsa.ExportSubjectPublicKeyInfo();

        // Load the public key into RsaKeyProvider so GetPublicKeyBase64() works correctly.
        // Decrypt() will not be called — AzureKeyVaultDecryptProvider handles that.
        _rsaKeyProvider.LoadPublicKeyOnly(spki);

        _logger.LogInformation(
            "[SecureRequest.AzureKeyVault] HSM mode active. " +
            "Public key loaded from Key Vault key '{KeyName}'. " +
            "All decryption will be performed in Key Vault — private key never enters the app.",
            _keyName);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
