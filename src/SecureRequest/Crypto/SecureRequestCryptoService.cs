using System.Security.Cryptography;
using System.Text;

namespace SecureRequest.Crypto;

/// <summary>
/// Default implementation of <see cref="ISecureRequestCryptoService"/>.
/// Algorithms: RSA-OAEP-SHA256 · AES-256-GCM · HMAC-SHA256 · SHA-256.
/// </summary>
public class SecureRequestCryptoService : ISecureRequestCryptoService
{
    private const int AesIvSize   = 12;   // GCM standard IV
    private const int AesTagSize  = 16;   // 128-bit authentication tag
    private const int AesKeySize  = 32;   // AES-256
    private const int HmacKeySize = 32;   // HMAC-SHA256
    private const int SecretSize  = AesKeySize + HmacKeySize; // 64 bytes total

    // SHA-256 of empty string — returned when there is no body to hash.
    private const string EmptyBodyHash =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private readonly RsaKeyProvider    _rsaKeyProvider;
    private readonly IRsaDecryptProvider _rsaDecryptProvider;

    /// <summary>
    /// Initializes the service with the singleton <see cref="RsaKeyProvider"/> and the
    /// configured <see cref="IRsaDecryptProvider"/> (defaults to <see cref="LocalRsaDecryptProvider"/>).
    /// </summary>
    public SecureRequestCryptoService(RsaKeyProvider rsaKeyProvider, IRsaDecryptProvider rsaDecryptProvider)
    {
        _rsaKeyProvider     = rsaKeyProvider     ?? throw new ArgumentNullException(nameof(rsaKeyProvider));
        _rsaDecryptProvider = rsaDecryptProvider ?? throw new ArgumentNullException(nameof(rsaDecryptProvider));
    }

    // ── RSA key decryption ────────────────────────────────────────────────────

    /// <inheritdoc/>
    public byte[] DecryptSecretKey(byte[] encryptedSecret)
    {
        var secret = _rsaKeyProvider.Decrypt(encryptedSecret);

        if (secret.Length != SecretSize)
            throw new CryptographicException(
                $"[SecureRequest] Decrypted secret must be {SecretSize} bytes " +
                $"(got {secret.Length}). Possible key mismatch.");

        return secret;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Routes through <see cref="IRsaDecryptProvider"/> — when a cloud HSM provider is
    /// registered (e.g. <c>AzureKeyVaultDecryptProvider</c>), decryption happens remotely
    /// and the private key never touches process memory.
    /// </remarks>
    public async Task<byte[]> DecryptSecretKeyAsync(
        byte[] encryptedSecret,
        CancellationToken cancellationToken = default)
    {
        var secret = await _rsaDecryptProvider.DecryptAsync(encryptedSecret, cancellationToken);

        if (secret.Length != SecretSize)
            throw new CryptographicException(
                $"[SecureRequest] Decrypted secret must be {SecretSize} bytes " +
                $"(got {secret.Length}). Possible key mismatch or wrong RSA key.");

        return secret;
    }

    // ── AES-256-GCM body decryption ───────────────────────────────────────────

    /// <inheritdoc/>
    public byte[] Decrypt(byte[] encryptedPayload, byte[] aesKey)
    {
        if (aesKey.Length != AesKeySize)
            throw new ArgumentException($"AES key must be {AesKeySize} bytes.", nameof(aesKey));

        if (encryptedPayload.Length < AesIvSize + AesTagSize)
            throw new CryptographicException("[SecureRequest] Encrypted payload is too short.");

        // Wire format: IV(12) + ciphertext + tag(16)
        var iv         = encryptedPayload[..AesIvSize];
        var tag        = encryptedPayload[^AesTagSize..];
        var ciphertext = encryptedPayload[AesIvSize..^AesTagSize];

        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(aesKey, AesTagSize);
        aes.Decrypt(iv, ciphertext, tag, plaintext);

        return plaintext;
    }

    // ── Body hashing ──────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public string ComputeBodyHash(byte[] body)
    {
        if (body.Length == 0) return EmptyBodyHash;

        var hash = SHA256.HashData(body);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ── HMAC signature ────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public string ComputeSignature(
        string method, string path, string query,
        string timestamp, string nonce, string bodyHexHash,
        byte[] hmacKey)
    {
        var canonical = string.Join('\n', method.ToUpperInvariant(), path, query, timestamp, nonce, bodyHexHash);
        var bytes     = Encoding.UTF8.GetBytes(canonical);

        var mac = HMACSHA256.HashData(hmacKey, bytes);
        return Convert.ToBase64String(mac);
    }

    // ── Constant-time comparison ──────────────────────────────────────────────

    /// <inheritdoc/>
    public bool ValidateSignature(string expected, string actual)
    {
        // Decode to bytes first so we always compare equal-length arrays (prevents timing leaks).
        try
        {
            var a = Convert.FromBase64String(expected);
            var b = Convert.FromBase64String(actual);
            return CryptographicOperations.FixedTimeEquals(a, b);
        }
        catch
        {
            return false;
        }
    }
}
