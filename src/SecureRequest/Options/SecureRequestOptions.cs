namespace SecureRequest.Options;

/// <summary>
/// Configuration for the RSA + AES-256-GCM + HMAC secure-request pipeline.
/// Bind from appsettings under the key passed to <c>AddSecureRequest()</c> (default: "SecureRequest").
///
/// Feature matrix — EnableBodyEncryption and EnableHmacSigning are independent:
///   true  + true  → full pipeline — body encrypted AND signature verified (recommended for production)
///   false + true  → integrity only — body sent as plaintext, HMAC signature still verified
///   true  + false → confidentiality only — body encrypted, signature check skipped
///   false + false → anti-replay only — timestamp + nonce checked, no crypto on body
///   Enabled=false → bypass everything (useful in development / Swagger)
/// </summary>
public sealed class SecureRequestOptions
{
    /// <summary>Default appsettings section name: <c>"SecureRequest"</c>.</summary>
    public const string DefaultSectionName = "SecureRequest";

    /// <summary>
    /// Master switch. When <c>false</c> the entire middleware is bypassed.
    /// Default: <c>false</c> — opt-in per environment.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// When <c>true</c> the client AES-256-GCM encrypts the request body and the server
    /// decrypts it before passing the plaintext to controllers.
    /// Requires <c>X-Encrypted-Key</c> header. Default: <c>true</c>.
    /// </summary>
    public bool EnableBodyEncryption { get; set; } = true;

    /// <summary>
    /// When <c>true</c> the client HMAC-SHA256 signs a canonical string over the request
    /// and the server verifies the <c>X-Signature</c> header.
    /// Requires <c>X-Encrypted-Key</c> header. Default: <c>true</c>.
    /// </summary>
    public bool EnableHmacSigning { get; set; } = true;

    /// <summary>
    /// Maximum allowed clock-skew between client and server in seconds.
    /// Default: 300 s (5 minutes).
    /// </summary>
    public int TimestampToleranceSeconds { get; set; } = 300;

    /// <summary>
    /// How long a consumed nonce is retained in the cache to block replays.
    /// Must be greater than 2 × <see cref="TimestampToleranceSeconds"/>.
    /// Default: 700 s.
    /// </summary>
    public int NonceCacheTtlSeconds { get; set; } = 700;

    /// <summary>
    /// HTTP methods the pipeline enforces.
    /// Requests whose method is not in this list are bypassed automatically.
    /// Default: POST, PUT, PATCH.
    /// </summary>
    public List<string> SecuredMethods { get; set; } = new()
    {
        "POST", "PUT", "PATCH"
    };

    /// <summary>
    /// URL path segments (case-insensitive) that bypass the pipeline.
    /// The match is a substring check on the full display URL.
    /// Example: "/api/public" bypasses anything whose URL contains that segment.
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new();

    /// <summary>
    /// How often (in seconds) all running instances reload the RSA private key from the
    /// configured <see cref="KeyStorage.IRsaKeyStorageProvider"/>. This ensures that after
    /// <see cref="Services.ISecureRequestKeyRotationService.RotateKeyAsync"/> runs on any
    /// one instance, every other instance picks up the new key within this window — without
    /// requiring a restart or redeployment.
    ///
    /// Set to <c>0</c> to disable automatic reload entirely (single-instance deployments
    /// or when using a cloud HSM where no local private key is stored).
    ///
    /// Default: <c>300</c> seconds (5 minutes). Should be less than or equal to the
    /// time your deployment pipeline takes to roll out a restart to all instances.
    /// </summary>
    public int KeyReloadIntervalSeconds { get; set; } = 300;
}
