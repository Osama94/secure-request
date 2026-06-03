namespace SecureRequest.KeyStorage;

/// <summary>
/// Abstraction for storing and retrieving the RSA private key used by the secure-request pipeline.
///
/// Implement this interface to integrate with your preferred Key Management Service:
///   - AWS Secrets Manager / AWS KMS
///   - Azure Key Vault
///   - Google Cloud Secret Manager
///   - HashiCorp Vault
///   - Any other secure store
///
/// The default implementation (<see cref="DistributedCacheKeyStorageProvider"/>) uses
/// <c>IDistributedCache</c> (Redis / in-memory) and is registered automatically
/// unless you override it via <c>AddSecureRequest().WithKeyStorage&lt;T&gt;()</c>.
///
/// <example>
/// Azure Key Vault example:
/// <code>
/// public class AzureKeyVaultStorageProvider : IRsaKeyStorageProvider
/// {
///     private readonly SecretClient _client;
///     private const string SecretName = "SecureRequest-RsaPrivateKey";
///
///     public AzureKeyVaultStorageProvider(SecretClient client) => _client = client;
///
///     public async Task&lt;byte[]?&gt; LoadPrivateKeyAsync(CancellationToken ct = default)
///     {
///         try
///         {
///             var secret = await _client.GetSecretAsync(SecretName, cancellationToken: ct);
///             return Convert.FromBase64String(secret.Value.Value);
///         }
///         catch (RequestFailedException ex) when (ex.Status == 404) { return null; }
///     }
///
///     public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken ct = default)
///     {
///         var base64 = Convert.ToBase64String(privateKeyBytes);
///         await _client.SetSecretAsync(SecretName, base64, ct);
///     }
/// }
/// </code>
/// </example>
///
/// <example>
/// AWS Secrets Manager example:
/// <code>
/// public class AwsSecretsManagerStorageProvider : IRsaKeyStorageProvider
/// {
///     private readonly IAmazonSecretsManager _client;
///     private const string SecretId = "secure-request/rsa-private-key";
///
///     public AwsSecretsManagerStorageProvider(IAmazonSecretsManager client) => _client = client;
///
///     public async Task&lt;byte[]?&gt; LoadPrivateKeyAsync(CancellationToken ct = default)
///     {
///         try
///         {
///             var response = await _client.GetSecretValueAsync(
///                 new GetSecretValueRequest { SecretId = SecretId }, ct);
///             return Convert.FromBase64String(response.SecretString);
///         }
///         catch (ResourceNotFoundException) { return null; }
///     }
///
///     public async Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken ct = default)
///     {
///         var base64 = Convert.ToBase64String(privateKeyBytes);
///         try
///         {
///             await _client.PutSecretValueAsync(
///                 new PutSecretValueRequest { SecretId = SecretId, SecretString = base64 }, ct);
///         }
///         catch (ResourceNotFoundException)
///         {
///             await _client.CreateSecretAsync(
///                 new CreateSecretRequest { Name = SecretId, SecretString = base64 }, ct);
///         }
///     }
/// }
/// </code>
/// </example>
/// </summary>
public interface IRsaKeyStorageProvider
{
    /// <summary>
    /// Loads the RSA private key (PKCS-8 bytes) from the store.
    /// Returns <c>null</c> if no key has been stored yet — the caller will then generate a new one.
    /// </summary>
    Task<byte[]?> LoadPrivateKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the RSA private key (PKCS-8 bytes) to the store.
    /// Called once on first startup when no key exists yet.
    /// </summary>
    Task StorePrivateKeyAsync(byte[] privateKeyBytes, CancellationToken cancellationToken = default);
}
