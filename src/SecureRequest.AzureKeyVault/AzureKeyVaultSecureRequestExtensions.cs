using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureRequest.Crypto;
using SecureRequest.Extensions;
using SecureRequest.Services;

namespace SecureRequest.AzureKeyVault;

/// <summary>
/// Extension methods that add Azure Key Vault integration to the SecureRequest pipeline.
///
/// Two modes are available:
///
/// <list type="bullet">
///   <item>
///     <b>Secrets mode</b> (<see cref="WithAzureKeyVault"/>) — the RSA private key is
///     generated locally and persisted as an Azure Key Vault <i>secret</i>.
///     Key Vault is used as durable, encrypted storage; decryption still happens in process.
///     Good for: centralised key storage, secret rotation, audit logs.
///   </item>
///   <item>
///     <b>True HSM mode</b> (<see cref="WithAzureKeyVaultHsm"/>) — the RSA key pair lives
///     entirely inside Azure Key Vault (or a Managed HSM). The private key <b>never</b> leaves
///     the vault; decryption is delegated to Key Vault's <c>Decrypt</c> API.
///     Good for: highest security, compliance requirements (FIPS 140-2/3, PCI-DSS, etc.).
///   </item>
/// </list>
/// </summary>
public static class AzureKeyVaultSecureRequestExtensions
{
    // ── Mode 1: Secrets (private key stored as a secret) ─────────────────────

    /// <summary>
    /// Replaces the default <c>DistributedCacheKeyStorageProvider</c> with
    /// <see cref="AzureKeyVaultKeyStorageProvider"/>, storing the RSA private key
    /// as a secret in Azure Key Vault.
    ///
    /// <para>
    /// The private key is held in memory during request processing; Key Vault acts as
    /// durable encrypted storage for the key bytes.
    /// For zero-export HSM mode use <see cref="WithAzureKeyVaultHsm"/> instead.
    /// </para>
    ///
    /// <example>
    /// Minimal setup (uses <see cref="DefaultAzureCredential"/> — works with Managed Identity,
    /// environment variables, Visual Studio, Azure CLI, and more):
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAzureKeyVault("https://your-vault.vault.azure.net/");
    /// </code>
    /// </example>
    ///
    /// <example>
    /// Custom secret name and explicit credential:
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAzureKeyVault(
    ///         keyVaultUri : "https://your-vault.vault.azure.net/",
    ///         secretName  : "MyApp-RsaPrivateKey",
    ///         credential  : new ClientSecretCredential(tenantId, clientId, clientSecret));
    /// </code>
    /// </example>
    /// </summary>
    /// <param name="builder">The <see cref="SecureRequestBuilder"/> returned by <c>AddSecureRequest()</c>.</param>
    /// <param name="keyVaultUri">Full URI of the Azure Key Vault, e.g. <c>https://my-vault.vault.azure.net/</c>.</param>
    /// <param name="secretName">
    /// Name of the secret that will hold the RSA private key.
    /// Defaults to <see cref="AzureKeyVaultKeyStorageProvider.DefaultSecretName"/>.
    /// </param>
    /// <param name="credential">
    /// Azure credential to use. Defaults to <see cref="DefaultAzureCredential"/>,
    /// which supports Managed Identity, environment variables, Visual Studio, Azure CLI, and more.
    /// </param>
    /// <returns>The same <see cref="SecureRequestBuilder"/> for further chaining.</returns>
    public static SecureRequestBuilder WithAzureKeyVault(
        this SecureRequestBuilder builder,
        string                    keyVaultUri,
        string                    secretName = AzureKeyVaultKeyStorageProvider.DefaultSecretName,
        TokenCredential?          credential = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyVaultUri);

        return builder.WithKeyStorage(sp =>
        {
            var cred   = credential ?? new DefaultAzureCredential();
            var client = new SecretClient(new Uri(keyVaultUri), cred);
            var logger = sp.GetRequiredService<ILogger<AzureKeyVaultKeyStorageProvider>>();

            return new AzureKeyVaultKeyStorageProvider(client, secretName, logger);
        });
    }

    // ── Mode 2: True HSM (private key never leaves Key Vault) ────────────────

    /// <summary>
    /// Wires up true HSM mode: the RSA key pair lives entirely inside Azure Key Vault
    /// (or a Managed HSM) and the <b>private key never leaves the vault</b>.
    ///
    /// <para>What this method does:</para>
    /// <list type="number">
    ///   <item>Removes <c>RsaKeyInitializerService</c> (no local key generation/loading).</item>
    ///   <item>Registers <see cref="AzureKeyVaultHsmInitializerService"/> — fetches the RSA public
    ///         key from Key Vault at startup so <c>GET /api/secure/public-key</c> works correctly.</item>
    ///   <item>Registers <see cref="AzureKeyVaultDecryptProvider"/> as <c>IRsaDecryptProvider</c> —
    ///         each request sends the encrypted AES secret to Key Vault's <c>Decrypt</c> API and
    ///         receives the plaintext; the private key never touches process memory.</item>
    ///   <item>Calls <c>WithMemoryStorage()</c> — no Redis or Key Vault secret needed for key storage.</item>
    /// </list>
    ///
    /// <para>
    /// <b>Prerequisites:</b> the RSA key named <paramref name="keyName"/> must already exist in
    /// Key Vault (type: RSA or RSA-HSM, key ops: <c>decrypt</c>). The identity used must have
    /// <c>Key Vault Crypto User</c> and <c>Key Vault Crypto Service Encryption User</c> roles.
    /// </para>
    ///
    /// <example>
    /// Minimal setup (recommended for production: use <see cref="ManagedIdentityCredential"/>):
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAzureKeyVaultHsm(
    ///         keyVaultUri : "https://your-vault.vault.azure.net/",
    ///         keyName     : "secure-request-rsa-key");
    /// </code>
    /// </example>
    ///
    /// <example>
    /// With explicit credential (local dev or CI):
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithAzureKeyVaultHsm(
    ///         keyVaultUri : "https://your-vault.vault.azure.net/",
    ///         keyName     : "secure-request-rsa-key",
    ///         credential  : new ClientSecretCredential(tenantId, clientId, clientSecret));
    /// </code>
    /// </example>
    /// </summary>
    /// <param name="builder">The <see cref="SecureRequestBuilder"/> returned by <c>AddSecureRequest()</c>.</param>
    /// <param name="keyVaultUri">Full URI of the Azure Key Vault, e.g. <c>https://my-vault.vault.azure.net/</c>.</param>
    /// <param name="keyName">Name of the RSA key in Key Vault (must already exist with <c>decrypt</c> operation enabled).</param>
    /// <param name="credential">
    /// Azure credential. Defaults to <see cref="DefaultAzureCredential"/>.
    /// In production use <see cref="ManagedIdentityCredential"/> for a smaller, faster credential chain.
    /// </param>
    /// <returns>The same <see cref="SecureRequestBuilder"/> for further chaining.</returns>
    public static SecureRequestBuilder WithAzureKeyVaultHsm(
        this SecureRequestBuilder builder,
        string                    keyVaultUri,
        string                    keyName,
        TokenCredential?          credential = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyVaultUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);

        var cred       = credential ?? new DefaultAzureCredential();
        var vaultUri   = new Uri(keyVaultUri);
        var keyClient  = new KeyClient(vaultUri, cred);
        var cryptoClient = new CryptographyClient(
            new Uri($"{keyVaultUri.TrimEnd('/')}/keys/{keyName}"), cred);

        var services = builder.Services;

        // 1. Remove the default local key-init hosted service.
        builder.RemoveHostedService<RsaKeyInitializerService>();

        // 2. Register the HSM initializer that loads the public key at startup.
        services.AddSingleton(keyClient);
        services.AddSingleton(sp => new AzureKeyVaultHsmInitializerService(
            sp.GetRequiredService<SecureRequest.Crypto.RsaKeyProvider>(),
            keyClient,
            keyName,
            sp.GetRequiredService<ILogger<AzureKeyVaultHsmInitializerService>>()));
        services.AddHostedService(sp =>
            sp.GetRequiredService<AzureKeyVaultHsmInitializerService>());

        // 3. Register AzureKeyVaultDecryptProvider as IRsaDecryptProvider.
        builder.WithDecryptProvider(sp => new AzureKeyVaultDecryptProvider(
            cryptoClient,
            sp.GetRequiredService<ILogger<AzureKeyVaultDecryptProvider>>()));

        // 4. Use memory storage — no private key to persist locally.
        builder.WithMemoryStorage();

        return builder;
    }
}
