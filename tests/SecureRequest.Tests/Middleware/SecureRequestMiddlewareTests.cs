using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SecureRequest.Crypto;
using SecureRequest.Extensions;
using SecureRequest.KeyStorage;
using SecureRequest.Options;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureRequest.Tests.Middleware;

/// <summary>
/// Integration tests for <see cref="SecureRequest.Middleware.SecureRequestMiddleware"/>.
/// Spins up a real ASP.NET Core TestHost with the full pipeline.
/// </summary>
public class SecureRequestMiddlewareTests : IAsyncLifetime
{
    private HttpClient _client = null!;
    private TestServer _server = null!;
    private RsaKeyProvider _rsaKeyProvider = null!;

    public async Task InitializeAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddDistributedMemoryCache();
                    services.AddRouting();

                    // Register RSA key provider as singleton so we can access it in tests
                    var rsaKeyProvider = new RsaKeyProvider();
                    rsaKeyProvider.GenerateAndExportPrivateKey();
                    services.AddSingleton(rsaKeyProvider);
                    services.AddSingleton<IRsaPublicKeyProvider>(rsaKeyProvider);
                    services.AddTransient<ISecureRequestCryptoService, SecureRequestCryptoService>();

                    services.Configure<SecureRequestOptions>(o =>
                    {
                        o.Enabled              = true;
                        o.EnableBodyEncryption = true;
                        o.EnableHmacSigning    = true;
                        o.ExcludedPaths        = new() { "/excluded" };
                        o.SecuredMethods       = new() { "POST", "PUT", "PATCH" };
                        o.TimestampToleranceSeconds = 300;
                        o.NonceCacheTtlSeconds = 700;
                    });
                });

                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseSecureRequest();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapPost("/api/test", async ctx =>
                        {
                            var body = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
                            await ctx.Response.WriteAsync(body);
                        });
                        endpoints.MapGet("/api/test", ctx =>
                        {
                            ctx.Response.StatusCode = 200;
                            return Task.CompletedTask;
                        });
                        endpoints.MapPost("/excluded", ctx =>
                        {
                            ctx.Response.StatusCode = 200;
                            return Task.CompletedTask;
                        });
                    });
                });
            })
            .StartAsync();

        _server         = host.GetTestServer();
        _client         = _server.CreateClient();
        _rsaKeyProvider = _server.Services.GetRequiredService<RsaKeyProvider>();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _server.Dispose();
        _rsaKeyProvider.Dispose();
        return Task.CompletedTask;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<HttpRequestMessage> BuildSecureRequestAsync(
        string method, string path, object? body,
        string? overrideTimestamp  = null,
        string? overrideNonce      = null,
        string? overrideSignature  = null,
        string? overrideEncryptKey = null,
        bool skipTimestamp         = false,
        bool skipNonce             = false,
        bool skipSignature         = false,
        bool skipEncryptedKey      = false)
    {
        var timestamp = overrideTimestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce     = overrideNonce     ?? Guid.NewGuid().ToString();

        // Generate per-request AES + HMAC keys
        var aesKeyBytes  = new byte[32];
        var hmacKeyBytes = new byte[32];
        Random.Shared.NextBytes(aesKeyBytes);
        Random.Shared.NextBytes(hmacKeyBytes);

        // Encrypt body with AES-256-GCM
        var plaintextBytes   = body != null
            ? Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body))
            : Array.Empty<byte>();

        byte[] encryptedBodyBytes;
        string encryptedBodyBase64;

        if (plaintextBytes.Length > 0)
        {
            var iv         = new byte[12];
            Random.Shared.NextBytes(iv);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag        = new byte[16];

            using var aes = new AesGcm(aesKeyBytes, 16);
            aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

            encryptedBodyBytes = new byte[iv.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(iv, 0, encryptedBodyBytes, 0, iv.Length);
            Buffer.BlockCopy(ciphertext, 0, encryptedBodyBytes, iv.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, encryptedBodyBytes, iv.Length + ciphertext.Length, tag.Length);
            encryptedBodyBase64 = Convert.ToBase64String(encryptedBodyBytes);
        }
        else
        {
            encryptedBodyBytes  = Array.Empty<byte>();
            encryptedBodyBase64 = string.Empty;
        }

        // Compute body hash (SHA-256 of encrypted bytes)
        var bodyHash = encryptedBodyBytes.Length > 0
            ? Convert.ToHexString(SHA256.HashData(encryptedBodyBytes)).ToLowerInvariant()
            : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Compute HMAC signature
        var canonical  = string.Join('\n', method.ToUpperInvariant(), path, "", timestamp, nonce, bodyHash);
        var hmacBytes  = HMACSHA256.HashData(hmacKeyBytes, Encoding.UTF8.GetBytes(canonical));
        var signature  = Convert.ToBase64String(hmacBytes);

        // RSA-encrypt 64-byte secret
        var secret = new byte[64];
        Buffer.BlockCopy(aesKeyBytes,  0, secret, 0,  32);
        Buffer.BlockCopy(hmacKeyBytes, 0, secret, 32, 32);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_rsaKeyProvider.GetPublicKeySpki(), out _);
        var encryptedKey = Convert.ToBase64String(rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA256));

        // Build request
        var request = new HttpRequestMessage(new HttpMethod(method), path);

        if (!string.IsNullOrEmpty(encryptedBodyBase64))
            request.Content = new StringContent(encryptedBodyBase64, Encoding.UTF8, "text/plain");
        else
            request.Content = new StringContent(string.Empty, Encoding.UTF8, "text/plain");

        if (!skipTimestamp)   request.Headers.TryAddWithoutValidation("X-Timestamp",     overrideTimestamp ?? timestamp);
        if (!skipNonce)       request.Headers.TryAddWithoutValidation("X-Nonce",          overrideNonce     ?? nonce);
        if (!skipSignature)   request.Headers.TryAddWithoutValidation("X-Signature",      overrideSignature ?? signature);
        if (!skipEncryptedKey) request.Headers.TryAddWithoutValidation("X-Encrypted-Key", overrideEncryptKey ?? encryptedKey);

        return await Task.FromResult(request);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidRequest_Returns200_AndDecryptsBody()
    {
        var body    = new { name = "Osama", role = "admin" };
        var request = await BuildSecureRequestAsync("POST", "/api/test", body);

        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var responseBody = await response.Content.ReadAsStringAsync();
        responseBody.Should().Contain("Osama");
    }

    // ── GET bypassed ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetRequest_IsBypassed_Returns200()
    {
        var response = await _client.GetAsync("/api/test");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Excluded path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ExcludedPath_IsBypassed_Returns200()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/excluded");
        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");

        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Missing headers ───────────────────────────────────────────────────────

    [Fact]
    public async Task MissingTimestamp_Returns422()
    {
        var request = await BuildSecureRequestAsync("POST", "/api/test", new { }, skipTimestamp: true);
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task MissingNonce_Returns422()
    {
        var request = await BuildSecureRequestAsync("POST", "/api/test", new { }, skipNonce: true);
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task MissingEncryptedKey_Returns422()
    {
        var request = await BuildSecureRequestAsync("POST", "/api/test", new { }, skipEncryptedKey: true);
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task MissingSignature_Returns422()
    {
        var request = await BuildSecureRequestAsync("POST", "/api/test", new { }, skipSignature: true);
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    // ── Timestamp validation ──────────────────────────────────────────────────

    [Fact]
    public async Task ExpiredTimestamp_Returns422()
    {
        var oldTimestamp = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 400).ToString(); // > 300s tolerance
        var request      = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideTimestamp: oldTimestamp);
        var response     = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task FutureTimestamp_Returns422()
    {
        var futureTimestamp = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 400).ToString();
        var request         = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideTimestamp: futureTimestamp);
        var response        = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task NonNumericTimestamp_Returns422()
    {
        var request  = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideTimestamp: "not-a-number");
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    // ── Nonce anti-replay ─────────────────────────────────────────────────────

    [Fact]
    public async Task ReplayedNonce_Returns422()
    {
        var nonce    = Guid.NewGuid().ToString();
        var request1 = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideNonce: nonce);
        var request2 = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideNonce: nonce);

        var response1 = await _client.SendAsync(request1);
        var response2 = await _client.SendAsync(request2);

        response1.StatusCode.Should().Be(HttpStatusCode.OK);
        response2.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    // ── Tampered body / wrong key ─────────────────────────────────────────────

    [Fact]
    public async Task TamperedEncryptedKey_Returns422()
    {
        var request  = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideEncryptKey: Convert.ToBase64String(new byte[256]));
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    [Fact]
    public async Task InvalidSignature_Returns422()
    {
        var request  = await BuildSecureRequestAsync("POST", "/api/test", new { }, overrideSignature: Convert.ToBase64String(new byte[32]));
        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
    }

    // ── Error response format ─────────────────────────────────────────────────

    [Fact]
    public async Task ErrorResponse_HasCorrectJsonStructure()
    {
        var request  = await BuildSecureRequestAsync("POST", "/api/test", new { }, skipTimestamp: true);
        var response = await _client.SendAsync(request);
        var json     = await response.Content.ReadAsStringAsync();

        var doc = JsonDocument.Parse(json);
        doc.RootElement.TryGetProperty("error", out var error).Should().BeTrue();
        error.TryGetProperty("code",    out _).Should().BeTrue();
        error.TryGetProperty("message", out _).Should().BeTrue();
    }
}
