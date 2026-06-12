using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureRequest.Crypto;
using SecureRequest.Options;
using System.Text;
using System.Text.Json;

namespace SecureRequest.Middleware;

/// <summary>
/// ASP.NET Core middleware that enforces the secure-request pipeline.
///
/// Steps (which run depends on <see cref="SecureRequestOptions.EnableBodyEncryption"/>
/// and <see cref="SecureRequestOptions.EnableHmacSigning"/>):
///
///   1. Bypass check     — OPTIONS, excluded paths, methods not in SecuredMethods → pass through.
///   2. Header presence  — X-Timestamp + X-Nonce always; X-Encrypted-Key when crypto active;
///                         X-Signature when HMAC active.
///   3. RSA key decrypt  — X-Encrypted-Key → 32-byte AES key + 32-byte HMAC key.
///   4. Timestamp check  — rejects drift > TimestampToleranceSeconds.
///   5. Nonce check      — rejects replayed nonces via IDistributedCache.
///   6. Body handling    — decrypts when EnableBodyEncryption=true, reads raw otherwise.
///   7. HMAC verify      — verifies X-Signature when EnableHmacSigning=true.
///   8. Nonce burn       — stores nonce (TTL = NonceCacheTtlSeconds).
///   9. Body replace     — swaps encrypted/raw body with plaintext for downstream handlers.
/// </summary>
public sealed class SecureRequestMiddleware
{
    private readonly RequestDelegate             _next;
    private readonly ILogger<SecureRequestMiddleware> _logger;
    private readonly SecureRequestOptions        _options;

    /// <summary>Initializes the middleware with the pipeline delegate, logger, and options.</summary>
    public SecureRequestMiddleware(
        RequestDelegate next,
        ILogger<SecureRequestMiddleware> logger,
        IOptions<SecureRequestOptions> options)
    {
        _next    = next    ?? throw new ArgumentNullException(nameof(next));
        _logger  = logger  ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>Processes the HTTP request through the secure-request pipeline.</summary>
    public async Task InvokeAsync(HttpContext context, IDistributedCache cache)
    {
        if (IsExcluded(context))
        {
            await _next(context);
            return;
        }

        var crypto        = context.RequestServices.GetRequiredService<ISecureRequestCryptoService>();
        var useEncryption = _options.EnableBodyEncryption;
        var useHmac       = _options.EnableHmacSigning;
        var needKeyHeader = useEncryption || useHmac;

        // ── Step 2 · Header presence ──────────────────────────────────────────
        if (!TryGetHeader(context, "X-Timestamp", out var timestampStr) ||
            !TryGetHeader(context, "X-Nonce",     out var nonce))
        {
            _logger.LogInformation(
                "[SecureRequest] Missing X-Timestamp or X-Nonce. Path={Path} Method={Method}",
                context.Request.Path, context.Request.Method);
            await WriteErrorAsync(context, "Missing required security headers.");
            return;
        }

        var encryptedKeyB64 = string.Empty;
        var clientSignature = string.Empty;

        if (needKeyHeader && !TryGetHeader(context, "X-Encrypted-Key", out encryptedKeyB64))
        {
            _logger.LogInformation(
                "[SecureRequest] Missing X-Encrypted-Key. Path={Path}", context.Request.Path);
            await WriteErrorAsync(context, "Missing required security headers.");
            return;
        }

        if (useHmac && !TryGetHeader(context, "X-Signature", out clientSignature))
        {
            _logger.LogInformation(
                "[SecureRequest] Missing X-Signature. Path={Path}", context.Request.Path);
            await WriteErrorAsync(context, "Missing required security headers.");
            return;
        }

        // ── Step 3 · Decrypt per-request AES + HMAC keys ─────────────────────
        byte[] aesKey  = Array.Empty<byte>();
        byte[] hmacKey = Array.Empty<byte>();

        if (needKeyHeader)
        {
            try
            {
                var encryptedKeyBytes = Convert.FromBase64String(encryptedKeyB64.Trim());
                // Use async path — routes through IRsaDecryptProvider.
                // With LocalRsaDecryptProvider this is a completed task (no I/O).
                // With a cloud HSM provider (Azure Key Vault, AWS KMS) this is a real async call.
                var secret = await crypto.DecryptSecretKeyAsync(encryptedKeyBytes, context.RequestAborted);
                aesKey  = secret[..32];
                hmacKey = secret[32..];
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "[SecureRequest] X-Encrypted-Key decryption failed. Path={Path}",
                    context.Request.Path);
                await WriteErrorAsync(context, "Invalid security headers.");
                return;
            }
        }

        // ── Step 4 · Timestamp validation ─────────────────────────────────────
        if (!long.TryParse(timestampStr, out var requestTimestamp))
        {
            await WriteErrorAsync(context, "Invalid timestamp.");
            return;
        }

        var clockDrift = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - requestTimestamp);
        if (clockDrift > _options.TimestampToleranceSeconds)
        {
            _logger.LogInformation(
                "[SecureRequest] Timestamp rejected. Drift={Drift}s Path={Path}",
                clockDrift, context.Request.Path);
            await WriteErrorAsync(context, "Request timestamp out of acceptable range.");
            return;
        }

        // ── Step 5 · Nonce validation (anti-replay) ───────────────────────────
        if (string.IsNullOrWhiteSpace(nonce) || nonce.Length < 8 || nonce.Length > 128)
        {
            _logger.LogInformation("[SecureRequest] X-Nonce format invalid.");
            await WriteErrorAsync(context, "Invalid nonce.");
            return;
        }

        var nonceCacheKey = $"secure_request:nonce:{nonce}";
        if (await cache.GetStringAsync(nonceCacheKey, context.RequestAborted) is not null)
        {
            _logger.LogWarning(
                "[SecureRequest] Replay detected. Nonce={Nonce} Path={Path}",
                nonce, context.Request.Path);
            await WriteErrorAsync(context, "Duplicate request detected.");
            return;
        }

        // ── Step 6 · Read body + optional decryption ─────────────────────────
        context.Request.EnableBuffering();

        byte[] rawBodyBytes;
        await using (var ms = new MemoryStream())
        {
            await context.Request.Body.CopyToAsync(ms, context.RequestAborted);
            rawBodyBytes = ms.ToArray();
        }

        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] bytesForHmac   = Array.Empty<byte>();

        if (useEncryption)
        {
            if (rawBodyBytes.Length > 0)
            {
                if (!TryBase64Decode(rawBodyBytes, out var encryptedBytes))
                {
                    _logger.LogInformation(
                        "[SecureRequest] Body is not valid Base64. Path={Path}", context.Request.Path);
                    await WriteErrorAsync(context, "Invalid request body encoding.");
                    return;
                }

                try
                {
                    plaintextBytes = crypto.Decrypt(encryptedBytes!, aesKey);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "[SecureRequest] Body decryption failed. Path={Path}", context.Request.Path);
                    await WriteErrorAsync(context, "Body decryption failed.");
                    return;
                }

                bytesForHmac = encryptedBytes!; // HMAC signed over ciphertext
            }
        }
        else
        {
            plaintextBytes = rawBodyBytes;
            bytesForHmac   = rawBodyBytes; // HMAC signed over plaintext
        }

        // ── Step 7 · HMAC signature verification ──────────────────────────────
        if (useHmac)
        {
            var bodyHash = crypto.ComputeBodyHash(bytesForHmac);
            var path     = context.Request.Path.Value ?? "/";
            var query    = context.Request.QueryString.Value ?? string.Empty;

            var expectedSig = crypto.ComputeSignature(
                context.Request.Method, path, query, timestampStr, nonce, bodyHash, hmacKey);

            if (!crypto.ValidateSignature(expectedSig, clientSignature))
            {
                _logger.LogInformation(
                    "[SecureRequest] Signature mismatch. Path={Path}", context.Request.Path);
                await WriteErrorAsync(context, "Request signature is invalid.");
                return;
            }
        }

        // ── Step 8 · Burn nonce ────────────────────────────────────────────────
        await cache.SetStringAsync(
            nonceCacheKey, "1",
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.NonceCacheTtlSeconds)
            },
            context.RequestAborted);

        // ── Step 9 · Replace body stream with plaintext ───────────────────────
        if (plaintextBytes.Length > 0)
        {
            context.Request.Body          = new MemoryStream(plaintextBytes);
            context.Request.ContentLength = plaintextBytes.Length;
            context.Request.ContentType   = "application/json; charset=utf-8";
        }
        else
        {
            context.Request.Body          = Stream.Null;
            context.Request.ContentLength = 0;
        }

        _logger.LogInformation(
            "[SecureRequest] Authenticated. Path={Path} Method={Method} Encryption={Enc} Hmac={Hmac}",
            context.Request.Path, context.Request.Method, useEncryption, useHmac);

        await _next(context);
    }

    #region Private helpers

    private bool IsExcluded(HttpContext context)
    {
        if (!_options.Enabled) return true;

        var method = context.Request.Method;
        if (method == "OPTIONS") return true;

        if (!_options.SecuredMethods.Any(m =>
                string.Equals(m, method, StringComparison.OrdinalIgnoreCase)))
            return true;

        var displayUrl = context.Request.GetDisplayUrl();
        return _options.ExcludedPaths.Any(p =>
            displayUrl.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryGetHeader(HttpContext context, string name, out string value)
    {
        value = context.Request.Headers[name].FirstOrDefault() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// Tries multiple decoding strategies to handle different Content-Type side-effects:
    ///   text/plain                    → raw base64 (correct)
    ///   application/json              → JSON-quoted: "BASE64=="
    ///   application/x-www-form-urlencoded → URL-encoded: + → %2B, / → %2F
    /// </summary>
    private static bool TryBase64Decode(byte[] rawBytes, out byte[]? decoded)
    {
        var raw = Encoding.UTF8.GetString(rawBytes).Trim();

        var candidates = new[]
        {
            raw,
            raw.Trim('"'),
            Uri.UnescapeDataString(raw),
            Uri.UnescapeDataString(raw.Trim('"'))
        };

        foreach (var candidate in candidates)
        {
            try
            {
                decoded = Convert.FromBase64String(candidate);
                return true;
            }
            catch { /* try next */ }
        }

        decoded = null;
        return false;
    }

    private static async Task WriteErrorAsync(HttpContext context, string message)
    {
        context.Response.StatusCode  = StatusCodes.Status422UnprocessableEntity;
        context.Response.ContentType = "application/json";

        var body = JsonSerializer.Serialize(new
        {
            error = new { code = 422, message }
        });

        await context.Response.WriteAsync(body);
    }

    #endregion
}
