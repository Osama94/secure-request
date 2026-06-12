using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.Extensions.Logging;
using SecureRequest.KeyStorage;

namespace SecureRequest.AwsKms;

/// <summary>
/// <see cref="IRsaKeyStorageProvider"/> implementation that stores the RSA private key
/// as a Base64-encoded secret inside AWS Secrets Manager.
///
/// AWS Secrets Manager handles encryption at rest (AES-256 via AWS KMS),
/// IAM-based access control, CloudTrail audit logging, and automatic secret rotation.
///
/// The private key is fetched over TLS and used in-process. For true zero-export
/// guarantees, use AWS KMS with RSA key pairs and perform decrypt operations
/// server-side via the KMS API instead.
/// </summary>
public sealed class AwsSecretsManagerKeyStorageProvider : IRsaKeyStorageProvider
{
    private readonly IAmazonSecretsManager _client;
    private readonly string _secretId;
    private readonly ILogger<AwsSecretsManagerKeyStorageProvider> _logger;

    /// <summary>Default secret ID used when none is specified.</summary>
    public const string DefaultSecretId = "secure-request/rsa-private-key";

    /// <summary>
    /// Initializes a new instance of <see cref="AwsSecretsManagerKeyStorageProvider"/>.
    /// </summary>
    /// <param name="client">An <see cref="IAmazonSecretsManager"/> client (injected or created directly).</param>
    /// <param name="secretId">The Secrets Manager secret ID or ARN that holds the RSA private key.</param>
    /// <param name="logger">Logger injected by DI.</param>
    public AwsSecretsManagerKeyStorageProvider(
        IAmazonSecretsManager                              client,
        string                                            secretId,
        ILogger<AwsSecretsManagerKeyStorageProvider> logger)
    {
        _client   = client   ?? throw new ArgumentNullException(nameof(client));
        _secretId = secretId ?? throw new ArgumentNullException(nameof(secretId));
        _logger   = logger   ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug(
                "[SecureRequest.AwsKms] Loading RSA private key from Secrets Manager secret '{SecretId}'.",
                _secretId);

            var response = await _client.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = _secretId },
                cancellationToken);

            var bytes = Convert.FromBase64String(response.SecretString);

            _logger.LogInformation(
                "[SecureRequest.AwsKms] RSA private key loaded from Secrets Manager secret '{SecretId}'.",
                _secretId);

            return bytes;
        }
        catch (ResourceNotFoundException)
        {
            _logger.LogInformation(
                "[SecureRequest.AwsKms] Secret '{SecretId}' not found — a new RSA key pair will be generated.",
                _secretId);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.AwsKms] Failed to load RSA private key from Secrets Manager secret '{SecretId}'.",
                _secretId);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default)
    {
        var base64 = Convert.ToBase64String(privateKeyBytes);

        try
        {
            // Try updating first (most common path after first startup).
            await _client.PutSecretValueAsync(
                new PutSecretValueRequest { SecretId = _secretId, SecretString = base64 },
                cancellationToken);

            _logger.LogInformation(
                "[SecureRequest.AwsKms] RSA private key updated in Secrets Manager secret '{SecretId}'.",
                _secretId);
        }
        catch (ResourceNotFoundException)
        {
            // Secret doesn't exist yet — create it on first startup.
            try
            {
                await _client.CreateSecretAsync(
                    new CreateSecretRequest { Name = _secretId, SecretString = base64 },
                    cancellationToken);

                _logger.LogInformation(
                    "[SecureRequest.AwsKms] RSA private key created in Secrets Manager secret '{SecretId}'.",
                    _secretId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "[SecureRequest.AwsKms] Failed to create Secrets Manager secret '{SecretId}'.",
                    _secretId);
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.AwsKms] Failed to store RSA private key in Secrets Manager secret '{SecretId}'.",
                _secretId);
            throw;
        }
    }
}
