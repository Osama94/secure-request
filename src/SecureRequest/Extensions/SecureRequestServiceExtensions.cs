using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authorization;
using SecureRequest.Crypto;
using SecureRequest.KeyStorage;
using SecureRequest.Middleware;
using SecureRequest.Options;
using SecureRequest.Services;
using Microsoft.Extensions.Hosting;

namespace SecureRequest.Extensions;

/// <summary>
/// Extension methods to register and activate the SecureRequest pipeline.
///
/// Minimal setup (uses distributed cache for key storage):
/// <code>
///   builder.Services.AddDistributedMemoryCache(); // or AddStackExchangeRedisCache(...)
///   builder.Services.AddSecureRequest(builder.Configuration);
///
///   var app = builder.Build();
///   app.UseSecureRequest();
///   app.MapSecureRequestPublicKey();
/// </code>
///
/// With a custom KMS provider (Azure Key Vault, AWS KMS, etc.):
/// <code>
///   builder.Services.AddSecureRequest(builder.Configuration)
///                   .WithKeyStorage&lt;AzureKeyVaultStorageProvider&gt;();
/// </code>
///
/// With inline options override:
/// <code>
///   builder.Services.AddSecureRequest(builder.Configuration, o =>
///   {
///       o.Enabled              = true;
///       o.EnableBodyEncryption = true;
///       o.EnableHmacSigning    = true;
///   }).WithKeyStorage&lt;MyKmsProvider&gt;();
/// </code>
/// </summary>
public static class SecureRequestServiceExtensions
{
    // ── IServiceCollection ────────────────────────────────────────────────────

    /// <summary>
    /// Registers all SecureRequest services and returns a <see cref="SecureRequestBuilder"/>
    /// for optional fluent configuration (e.g. custom key storage).
    /// </summary>
    /// <remarks>
    /// Unless <c>.WithKeyStorage&lt;T&gt;()</c> is called, the default key storage is
    /// <see cref="DistributedCacheKeyStorageProvider"/> which requires <c>IDistributedCache</c>
    /// to be registered (e.g. <c>AddStackExchangeRedisCache(…)</c> or <c>AddDistributedMemoryCache()</c>).
    /// </remarks>
    public static SecureRequestBuilder AddSecureRequest(
        this IServiceCollection       services,
        IConfiguration                configuration,
        string                        sectionName = SecureRequestOptions.DefaultSectionName,
        Action<SecureRequestOptions>? configure   = null)
    {
        services.Configure<SecureRequestOptions>(configuration.GetSection(sectionName));

        if (configure is not null)
            services.PostConfigure<SecureRequestOptions>(configure);

        services.AddSingleton<RsaKeyProvider>();
        services.AddSingleton<IRsaPublicKeyProvider>(sp => sp.GetRequiredService<RsaKeyProvider>());

        // Default decrypt provider — local in-process RSA.
        // Replace with a cloud HSM provider via .WithDecryptProvider<T>().
        services.AddSingleton<IRsaDecryptProvider, LocalRsaDecryptProvider>();

        services.AddTransient<ISecureRequestCryptoService, SecureRequestCryptoService>();
        services.AddHostedService<RsaKeyInitializerService>();

        // Background service that reloads the RSA key from storage every KeyReloadIntervalSeconds.
        // Ensures all load-balanced instances pick up key rotations without a restart.
        services.AddHostedService<RsaKeyReloaderService>();

        // Register default key storage — can be replaced by calling .WithKeyStorage<T>()
        services.AddScoped<IRsaKeyStorageProvider, DistributedCacheKeyStorageProvider>();

        // Key rotation service
        services.AddScoped<ISecureRequestKeyRotationService, SecureRequestKeyRotationService>();

        return new SecureRequestBuilder(services);
    }

    // ── IApplicationBuilder ───────────────────────────────────────────────────

    /// <summary>
    /// Adds <see cref="SecureRequestMiddleware"/> to the ASP.NET Core pipeline.
    /// Call this before <c>UseRouting()</c> / <c>UseAuthorization()</c>.
    /// </summary>
    public static IApplicationBuilder UseSecureRequest(this IApplicationBuilder app)
        => app.UseMiddleware<SecureRequestMiddleware>();

    // ── IEndpointRouteBuilder — public-key endpoint ───────────────────────────

    /// <summary>
    /// Maps a minimal-API endpoint that returns the server's RSA public key as Base64.
    /// Clients call this once to cache the key for encrypting X-Encrypted-Key headers.
    /// Default route: <c>GET /api/secure/public-key</c>
    /// </summary>
    /// <summary>
    /// Maps a minimal-API endpoint that returns the server's RSA public key as Base64.
    /// Clients call this once to cache the key for encrypting X-Encrypted-Key headers.
    /// Default route: <c>GET /api/secure/public-key</c>
    /// Responds with <c>Cache-Control: public, max-age=86400</c> so clients cache it for 24 hours.
    /// </summary>
    public static IEndpointRouteBuilder MapSecureRequestPublicKey(
        this IEndpointRouteBuilder endpoints,
        string route = "/api/secure/public-key")
    {
        endpoints.MapGet(route, (IRsaPublicKeyProvider provider, HttpContext ctx) =>
        {
            ctx.Response.Headers.CacheControl = "public, max-age=86400";
            return Results.Ok(new { publicKey = provider.GetPublicKeyBase64() });
        })
        .AllowAnonymous()
        .WithName("SecureRequest_PublicKey")
        .WithTags("Security");

        return endpoints;
    }

    /// <summary>
    /// Maps a protected minimal-API endpoint that triggers RSA key rotation.
    /// Default route: <c>POST /api/secure/rotate-key</c>
    ///
    /// ⚠️ This endpoint MUST be protected — apply an authorization policy:
    /// <code>
    ///   app.MapSecureRequestKeyRotation(policy: "AdminOnly");
    /// </code>
    /// After rotation, clients holding the old public key will receive a 422 on their next
    /// secured request, automatically re-fetch the new key, and retry transparently.
    /// </summary>
    public static IEndpointRouteBuilder MapSecureRequestKeyRotation(
        this IEndpointRouteBuilder endpoints,
        string route  = "/api/secure/rotate-key",
        string? policy = null)
    {
        var builder = endpoints.MapPost(route, async (ISecureRequestKeyRotationService rotation, CancellationToken ct) =>
        {
            var newPublicKey = await rotation.RotateKeyAsync(ct);
            return Results.Ok(new { message = "RSA key pair rotated successfully.", newPublicKey });
        })
        .WithName("SecureRequest_RotateKey")
        .WithTags("Security");

        if (policy is not null)
            builder.RequireAuthorization(policy);
        else
            builder.RequireAuthorization(); // require at minimum authenticated user

        return endpoints;
    }
}

// ── Fluent builder ─────────────────────────────────────────────────────────────

/// <summary>
/// Fluent builder returned by <see cref="SecureRequestServiceExtensions.AddSecureRequest"/>
/// for chaining optional configuration such as custom key storage providers.
/// </summary>
public sealed class SecureRequestBuilder
{
    private readonly IServiceCollection _services;

    internal SecureRequestBuilder(IServiceCollection services)
        => _services = services;

    /// <summary>
    /// Exposes the underlying <see cref="IServiceCollection"/> for advanced scenarios —
    /// for example, companion packages that need to register additional services or
    /// remove a built-in hosted service.
    /// </summary>
    public IServiceCollection Services => _services;

    /// <summary>
    /// Replaces the default <see cref="DistributedCacheKeyStorageProvider"/> with a custom
    /// <see cref="IRsaKeyStorageProvider"/> implementation — e.g. Azure Key Vault, AWS KMS,
    /// Google Cloud Secret Manager, or HashiCorp Vault.
    ///
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithKeyStorage&lt;AzureKeyVaultStorageProvider&gt;();
    /// </code>
    /// </example>
    /// </summary>
    public SecureRequestBuilder WithKeyStorage<TProvider>()
        where TProvider : class, IRsaKeyStorageProvider
    {
        // Remove the default registration and replace with the custom provider
        var descriptor = _services.FirstOrDefault(
            d => d.ServiceType == typeof(IRsaKeyStorageProvider));

        if (descriptor is not null)
            _services.Remove(descriptor);

        _services.AddScoped<IRsaKeyStorageProvider, TProvider>();

        return this;
    }

    /// <summary>
    /// Replaces the default key storage with a factory-based custom provider.
    /// Use this when your provider needs constructor arguments not available via DI.
    ///
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithKeyStorage(sp => new AwsSecretsManagerStorageProvider(
    ///         sp.GetRequiredService&lt;IAmazonSecretsManager&gt;(), "my-secret-id"));
    /// </code>
    /// </example>
    /// </summary>
    public SecureRequestBuilder WithKeyStorage(
        Func<IServiceProvider, IRsaKeyStorageProvider> factory)
    {
        var descriptor = _services.FirstOrDefault(
            d => d.ServiceType == typeof(IRsaKeyStorageProvider));

        if (descriptor is not null)
            _services.Remove(descriptor);

        _services.AddScoped<IRsaKeyStorageProvider>(factory);

        return this;
    }

    /// <summary>
    /// Switches to in-memory key storage — the RSA private key is held only in process memory
    /// and is not persisted to any external store.
    ///
    /// Useful for:
    /// <list type="bullet">
    ///   <item>Local development — no Redis required.</item>
    ///   <item>Single-instance deployments.</item>
    ///   <item>Cloud HSM mode — when the private key lives in a KMS and no local storage is needed.</item>
    /// </list>
    ///
    /// ⚠️ Not suitable for load-balanced production deployments without a cloud HSM
    /// decrypt provider, because each instance will generate its own key pair.
    /// </summary>
    public SecureRequestBuilder WithMemoryStorage()
    {
        var descriptor = _services.FirstOrDefault(
            d => d.ServiceType == typeof(IRsaKeyStorageProvider));

        if (descriptor is not null)
            _services.Remove(descriptor);

        // Singleton so the same instance persists the key for the app's lifetime.
        _services.AddSingleton<IRsaKeyStorageProvider, MemoryKeyStorageProvider>();

        return this;
    }

    /// <summary>
    /// Replaces the default <see cref="LocalRsaDecryptProvider"/> with a custom
    /// <see cref="IRsaDecryptProvider"/> — e.g. a cloud HSM provider that performs
    /// RSA decryption remotely so the private key never enters process memory.
    ///
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithDecryptProvider&lt;AzureKeyVaultDecryptProvider&gt;();
    /// </code>
    /// </example>
    /// </summary>
    public SecureRequestBuilder WithDecryptProvider<TProvider>()
        where TProvider : class, IRsaDecryptProvider
    {
        var descriptor = _services.FirstOrDefault(
            d => d.ServiceType == typeof(IRsaDecryptProvider));

        if (descriptor is not null)
            _services.Remove(descriptor);

        _services.AddSingleton<IRsaDecryptProvider, TProvider>();

        return this;
    }

    /// <summary>
    /// Replaces the default <see cref="LocalRsaDecryptProvider"/> with a factory-based
    /// custom <see cref="IRsaDecryptProvider"/>.
    ///
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddSecureRequest(builder.Configuration)
    ///     .WithDecryptProvider(sp => new AzureKeyVaultDecryptProvider(
    ///         sp.GetRequiredService&lt;CryptographyClient&gt;(),
    ///         sp.GetRequiredService&lt;ILogger&lt;AzureKeyVaultDecryptProvider&gt;&gt;()));
    /// </code>
    /// </example>
    /// </summary>
    public SecureRequestBuilder WithDecryptProvider(
        Func<IServiceProvider, IRsaDecryptProvider> factory)
    {
        var descriptor = _services.FirstOrDefault(
            d => d.ServiceType == typeof(IRsaDecryptProvider));

        if (descriptor is not null)
            _services.Remove(descriptor);

        _services.AddSingleton<IRsaDecryptProvider>(factory);

        return this;
    }

    /// <summary>
    /// Removes a registered <see cref="IHostedService"/> by implementation type.
    /// Used by companion packages that need to replace a built-in background service
    /// with a custom one (e.g. replacing <see cref="Services.RsaKeyInitializerService"/>
    /// with a cloud HSM key initializer).
    /// </summary>
    public SecureRequestBuilder RemoveHostedService<TService>()
        where TService : class, IHostedService
    {
        var descriptor = _services.FirstOrDefault(d =>
            d.ServiceType == typeof(IHostedService) &&
            d.ImplementationType == typeof(TService));

        if (descriptor is not null)
            _services.Remove(descriptor);

        return this;
    }
}
