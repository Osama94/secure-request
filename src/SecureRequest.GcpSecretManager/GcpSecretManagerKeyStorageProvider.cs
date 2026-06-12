using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using SecureRequest.KeyStorage;

namespace SecureRequest.GcpSecretManager;

/// <summary>
/// <see cref="IRsaKeyStorageProvider"/> implementation that stores the RSA private key
/// as a Base64-encoded secret version inside Google Cloud Secret Manager.
///
/// GCP Secret Manager handles encryption at rest (AES-256 with optional CMEK),
/// IAM-based access control, Cloud Audit Logs, and secret versioning.
///
/// The private key is fetched over TLS and used in-process.
/// </summary>
public sealed class GcpSecretManagerKeyStorageProvider : IRsaKeyStorageProvider
{
    private readonly SecretManagerServiceClient                     _client;
    private readonly string                                         _projectId;
    private readonly string                                         _secretId;
    private readonly ILogger<GcpSecretManagerKeyStorageProvider>    _logger;

    /// <summary>Default secret ID used when none is specified.</summary>
    public const string DefaultSecretId = "secure-request-rsa-private-key";

    /// <summary>
    /// Initializes a new instance of <see cref="GcpSecretManagerKeyStorageProvider"/>.
    /// </summary>
    /// <param name="client">An authenticated <see cref="SecretManagerServiceClient"/>.</param>
    /// <param name="projectId">The GCP project ID that owns the secret.</param>
    /// <param name="secretId">The Secret Manager secret ID. Defaults to <see cref="DefaultSecretId"/>.</param>
    /// <param name="logger">Logger injected by DI.</param>
    public GcpSecretManagerKeyStorageProvider(
        SecretManagerServiceClient                      client,
        string                                          projectId,
        string                                          secretId,
        ILogger<GcpSecretManagerKeyStorageProvider>     logger)
    {
        _client    = client    ?? throw new ArgumentNullException(nameof(client));
        _projectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        _secretId  = secretId  ?? throw new ArgumentNullException(nameof(secretId));
        _logger    = logger    ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default)
    {
        var secretVersionName = new SecretVersionName(_projectId, _secretId, "latest");

        try
        {
            _logger.LogDebug(
                "[SecureRequest.GcpSecretManager] Loading RSA private key from secret '{Project}/{SecretId}'.",
                _projectId, _secretId);

            var response = await _client.AccessSecretVersionAsync(
                secretVersionName, cancellationToken);

            var bytes = Convert.FromBase64String(
                response.Payload.Data.ToStringUtf8());

            _logger.LogInformation(
                "[SecureRequest.GcpSecretManager] RSA private key loaded from secret '{Project}/{SecretId}'.",
                _projectId, _secretId);

            return bytes;
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
        {
            _logger.LogInformation(
                "[SecureRequest.GcpSecretManager] Secret '{Project}/{SecretId}' not found — a new RSA key pair will be generated.",
                _projectId, _secretId);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.GcpSecretManager] Failed to load RSA private key from secret '{Project}/{SecretId}'.",
                _projectId, _secretId);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default)
    {
        // Use string literals for parent paths — avoids an extra GCP resource-name dependency.
        var secretParent  = $"projects/{_projectId}/secrets/{_secretId}";
        var projectParent = $"projects/{_projectId}";
        var base64        = Convert.ToBase64String(privateKeyBytes);
        var payload       = new SecretPayload { Data = ByteString.CopyFromUtf8(base64) };

        try
        {
            // Attempt to add a new version to an existing secret.
            await _client.AddSecretVersionAsync(
                new AddSecretVersionRequest { Parent = secretParent, Payload = payload },
                cancellationToken);

            _logger.LogInformation(
                "[SecureRequest.GcpSecretManager] RSA private key stored as new version in secret '{Project}/{SecretId}'.",
                _projectId, _secretId);
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
        {
            // Secret doesn't exist — create it first, then add the version.
            try
            {
                await _client.CreateSecretAsync(
                    new CreateSecretRequest
                    {
                        Parent   = projectParent,
                        SecretId = _secretId,
                        Secret   = new Secret
                        {
                            Replication = new Replication
                            {
                                Automatic = new Replication.Types.Automatic()
                            }
                        }
                    },
                    cancellationToken);

                await _client.AddSecretVersionAsync(
                    new AddSecretVersionRequest { Parent = secretParent, Payload = payload },
                    cancellationToken);

                _logger.LogInformation(
                    "[SecureRequest.GcpSecretManager] Created and stored RSA private key in new secret '{Project}/{SecretId}'.",
                    _projectId, _secretId);
            }
            catch (Exception innerEx)
            {
                _logger.LogError(innerEx,
                    "[SecureRequest.GcpSecretManager] Failed to create secret '{Project}/{SecretId}'.",
                    _projectId, _secretId);
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SecureRequest.GcpSecretManager] Failed to store RSA private key in secret '{Project}/{SecretId}'.",
                _projectId, _secretId);
            throw;
        }
    }
}
