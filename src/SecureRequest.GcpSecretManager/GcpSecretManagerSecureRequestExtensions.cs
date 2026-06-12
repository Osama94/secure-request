using Google.Cloud.SecretManager.V1;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureRequest.Extensions;

namespace SecureRequest.GcpSecretManager;

/// <summary>
/// Extension methods that add Google Cloud Secret Manager key storage to the SecureRequest pipeline.
/// </summary>
public static class GcpSecretManagerSecureRequestExtensions
{
    /// <summary>
    /// Replaces the default <c>DistributedCacheKeyStorageProvider</c> with
    /// <see cref="GcpSecretManagerKeyStorageProvider"/>, storing the RSA private key
    /// as a secret version in Google Cloud Secret Manager.
    ///
    /// <para>
    /// Application Default Credentials (ADC) are used automatically — they pick up
    /// Workload Identity in GKE, service account impersonation, <c>GOOGLE_APPLICATION_CREDENTIALS</c>,
    /// and <c>gcloud auth application-default login</c> in development.
    /// </para>
    ///
    /// <example>
    /// Minimal setup:
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithGcpSecretManager(projectId: "my-gcp-project");
    /// </code>
    /// </example>
    ///
    /// <example>
    /// Custom secret ID:
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithGcpSecretManager(
    ///         projectId : "my-gcp-project",
    ///         secretId  : "myapp-rsa-private-key");
    /// </code>
    /// </example>
    ///
    /// <example>
    /// Bring your own <see cref="SecretManagerServiceClient"/> (already in DI):
    /// <code>
    /// builder.Services.AddSingleton(SecretManagerServiceClient.Create());
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithGcpSecretManager(
    ///         projectId     : "my-gcp-project",
    ///         clientFactory : sp => sp.GetRequiredService&lt;SecretManagerServiceClient&gt;());
    /// </code>
    /// </example>
    /// </summary>
    /// <param name="builder">The <see cref="SecureRequestBuilder"/> returned by <c>AddSecureRequest()</c>.</param>
    /// <param name="projectId">GCP project ID that owns the secret.</param>
    /// <param name="secretId">
    /// Secret Manager secret ID. Defaults to <see cref="GcpSecretManagerKeyStorageProvider.DefaultSecretId"/>.
    /// </param>
    /// <param name="clientFactory">
    /// Optional factory to resolve a custom <see cref="SecretManagerServiceClient"/> from DI.
    /// When omitted, <see cref="SecretManagerServiceClient.CreateAsync"/> is called using ADC.
    /// </param>
    /// <returns>The same <see cref="SecureRequestBuilder"/> for further chaining.</returns>
    public static SecureRequestBuilder WithGcpSecretManager(
        this SecureRequestBuilder                                       builder,
        string                                                          projectId,
        string                                                          secretId      = GcpSecretManagerKeyStorageProvider.DefaultSecretId,
        Func<IServiceProvider, SecretManagerServiceClient>?             clientFactory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectId);

        return builder.WithKeyStorage(sp =>
        {
            var client = clientFactory is not null
                ? clientFactory(sp)
                : SecretManagerServiceClient.Create();   // uses Application Default Credentials

            var logger = sp.GetRequiredService<ILogger<GcpSecretManagerKeyStorageProvider>>();

            return new GcpSecretManagerKeyStorageProvider(client, projectId, secretId, logger);
        });
    }
}
