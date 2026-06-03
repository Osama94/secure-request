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
        services.AddTransient<ISecureRequestCryptoService, SecureRequestCryptoService>();
        services.AddHostedService<RsaKeyInitializerService>();

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
}
