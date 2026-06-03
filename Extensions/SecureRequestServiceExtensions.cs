using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureRequest.Crypto;
using SecureRequest.Middleware;
using SecureRequest.Options;
using SecureRequest.Services;

namespace SecureRequest.Extensions;

/// <summary>
/// Extension methods to register and activate the SecureRequest pipeline.
///
/// Minimal setup (appsettings-driven):
/// <code>
///   // Program.cs
///   builder.Services.AddSecureRequest(builder.Configuration);
///
///   var app = builder.Build();
///   app.UseSecureRequest();
///   app.MapSecureRequestPublicKey(); // GET /api/secure/public-key
/// </code>
///
/// Custom options:
/// <code>
///   builder.Services.AddSecureRequest(builder.Configuration, o =>
///   {
///       o.Enabled               = true;
///       o.EnableBodyEncryption  = true;
///       o.EnableHmacSigning     = true;
///       o.TimestampToleranceSeconds = 300;
///       o.NonceCacheTtlSeconds  = 700;
///       o.SecuredMethods        = new() { "POST", "PUT", "PATCH" };
///       o.ExcludedPaths         = new() { "/api/secure/public-key" };
///   });
/// </code>
/// </summary>
public static class SecureRequestServiceExtensions
{
    // ── IServiceCollection ────────────────────────────────────────────────────

    /// <summary>
    /// Registers all SecureRequest services.
    /// Reads options from <paramref name="configuration"/> section (default key: "SecureRequest").
    /// An optional <paramref name="configure"/> delegate overrides individual settings.
    /// </summary>
    /// <remarks>
    /// Requires <c>IDistributedCache</c> to be registered before this call
    /// (e.g. <c>services.AddStackExchangeRedisCache(…)</c> or <c>services.AddDistributedMemoryCache()</c>).
    /// </remarks>
    public static IServiceCollection AddSecureRequest(
        this IServiceCollection  services,
        IConfiguration           configuration,
        string                   sectionName = SecureRequestOptions.DefaultSectionName,
        Action<SecureRequestOptions>? configure = null)
    {
        // Bind options from configuration
        services.Configure<SecureRequestOptions>(configuration.GetSection(sectionName));

        // Allow inline overrides
        if (configure is not null)
            services.PostConfigure<SecureRequestOptions>(configure);

        // RSA key provider — singleton so it is shared across all requests
        services.AddSingleton<RsaKeyProvider>();
        services.AddSingleton<IRsaPublicKeyProvider>(sp => sp.GetRequiredService<RsaKeyProvider>());

        // Crypto service — transient is fine; no mutable state
        services.AddTransient<ISecureRequestCryptoService, SecureRequestCryptoService>();

        // Hosted service initialises the RSA key pair on startup
        services.AddHostedService<RsaKeyInitializerService>();

        return services;
    }

    // ── IApplicationBuilder ───────────────────────────────────────────────────

    /// <summary>
    /// Adds <see cref="SecureRequestMiddleware"/> to the ASP.NET Core pipeline.
    /// Call this before <c>UseRouting()</c> / <c>UseAuthorization()</c> so the body
    /// is decrypted before controller binding runs.
    /// </summary>
    public static IApplicationBuilder UseSecureRequest(this IApplicationBuilder app)
        => app.UseMiddleware<SecureRequestMiddleware>();

    // ── IEndpointRouteBuilder — public-key endpoint ───────────────────────────

    /// <summary>
    /// Maps a minimal-API endpoint that returns the server's RSA public key as a Base64 string.
    /// Clients call this once on startup to cache the key for encrypting X-Encrypted-Key headers.
    ///
    /// Default route: <c>GET /api/secure/public-key</c>
    /// Add this route to <see cref="SecureRequestOptions.ExcludedPaths"/> so the middleware
    /// does not try to verify its own public-key response.
    /// </summary>
    public static IEndpointRouteBuilder MapSecureRequestPublicKey(
        this IEndpointRouteBuilder endpoints,
        string route = "/api/secure/public-key")
    {
        endpoints.MapGet(route, (IRsaPublicKeyProvider provider) =>
            Results.Ok(new { publicKey = provider.GetPublicKeyBase64() }))
            .AllowAnonymous()
            .WithName("SecureRequest_PublicKey")
            .WithTags("Security");

        return endpoints;
    }
}
