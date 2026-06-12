using Amazon;
using Amazon.SecretsManager;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureRequest.Extensions;

namespace SecureRequest.AwsSecretsManager;

/// <summary>
/// Extension methods that add AWS Secrets Manager key storage to the SecureRequest pipeline.
/// </summary>
public static class AwsSecretsManagerSecureRequestExtensions
{
    /// <summary>
    /// Replaces the default <c>DistributedCacheKeyStorageProvider</c> with
    /// <see cref="AwsSecretsManagerKeyStorageProvider"/>, storing the RSA private key
    /// as a secret in AWS Secrets Manager.
    ///
    /// <example>
    /// Minimal setup (uses the default AWS credential chain — IAM role, environment
    /// variables, ~/.aws/credentials, etc.):
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAwsSecretsManager();
    /// </code>
    /// </example>
    ///
    /// <example>
    /// Custom secret ID and region:
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAwsSecretsManager(
    ///         secretId : "myapp/prod/rsa-key",
    ///         region   : RegionEndpoint.EUWest1);
    /// </code>
    /// </example>
    ///
    /// <example>
    /// Bring your own <see cref="IAmazonSecretsManager"/> (e.g. already registered in DI):
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAwsSecretsManager(
    ///         secretId      : "myapp/prod/rsa-key",
    ///         clientFactory : sp => sp.GetRequiredService&lt;IAmazonSecretsManager&gt;());
    /// </code>
    /// </example>
    /// </summary>
    /// <param name="builder">The <see cref="SecureRequestBuilder"/> returned by <c>AddSecureRequest()</c>.</param>
    /// <param name="secretId">
    /// The Secrets Manager secret ID or ARN. Defaults to
    /// <see cref="AwsSecretsManagerKeyStorageProvider.DefaultSecretId"/>.
    /// </param>
    /// <param name="region">
    /// AWS region endpoint. Defaults to <see cref="RegionEndpoint.USEast1"/>.
    /// Ignored when <paramref name="clientFactory"/> is provided.
    /// </param>
    /// <param name="clientFactory">
    /// Optional factory to resolve a custom <see cref="IAmazonSecretsManager"/> from DI.
    /// Use this when you register the AWS client yourself (e.g. with custom credentials).
    /// </param>
    /// <returns>The same <see cref="SecureRequestBuilder"/> for further chaining.</returns>
    public static SecureRequestBuilder WithAwsSecretsManager(
        this SecureRequestBuilder                               builder,
        string                                                  secretId      = AwsSecretsManagerKeyStorageProvider.DefaultSecretId,
        RegionEndpoint?                                         region        = null,
        Func<IServiceProvider, IAmazonSecretsManager>?          clientFactory = null)
    {
        return builder.WithKeyStorage(sp =>
        {
            var client = clientFactory is not null
                ? clientFactory(sp)
                : new AmazonSecretsManagerClient(region ?? RegionEndpoint.USEast1);

            var logger = sp.GetRequiredService<ILogger<AwsSecretsManagerKeyStorageProvider>>();

            return new AwsSecretsManagerKeyStorageProvider(client, secretId, logger);
        });
    }
}
