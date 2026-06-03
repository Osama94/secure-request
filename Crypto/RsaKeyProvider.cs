using System.Security.Cryptography;

namespace SecureRequest.Crypto;

/// <summary>
/// Singleton that holds the server's RSA-2048 key pair in memory.
///
/// Lifecycle:
///   - On first startup <see cref="RsaKeyInitializerService"/> checks the distributed cache.
///   - If a persisted PKCS-8 private key is found it calls <see cref="LoadFromPrivateKey"/>.
///   - Otherwise it calls <see cref="GenerateAndExportPrivateKey"/> and stores the result.
///   - All server instances behind a load balancer therefore share the same key pair.
/// </summary>
public sealed class RsaKeyProvider : IRsaPublicKeyProvider, IDisposable
{
    private RSA? _rsa;

    // ── Initialization ────────────────────────────────────────────────────────

    /// <summary>Loads an existing PKCS-8 private key (retrieved from the distributed cache).</summary>
    public void LoadFromPrivateKey(byte[] pkcs8PrivateKey)
    {
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
        Interlocked.Exchange(ref _rsa, rsa)?.Dispose();
    }

    /// <summary>
    /// Generates a fresh RSA-2048 key pair, stores it, and returns the PKCS-8 private key bytes
    /// so the caller can persist them to the distributed cache.
    /// </summary>
    public byte[] GenerateAndExportPrivateKey()
    {
        var rsa = RSA.Create(2048);
        Interlocked.Exchange(ref _rsa, rsa)?.Dispose();
        return rsa.ExportPkcs8PrivateKey();
    }

    // ── IRsaPublicKeyProvider ─────────────────────────────────────────────────

    /// <inheritdoc/>
    public string GetPublicKeyBase64() => Convert.ToBase64String(GetRsa().ExportSubjectPublicKeyInfo());

    // ── Internal use by SecureRequestCryptoService ────────────────────────────

    internal byte[] GetPublicKeySpki() => GetRsa().ExportSubjectPublicKeyInfo();

    internal byte[] Decrypt(byte[] ciphertext) =>
        GetRsa().Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RSA GetRsa() =>
        _rsa ?? throw new InvalidOperationException(
            "[SecureRequest] RSA key pair is not initialized yet. " +
            "Ensure AddSecureRequest() is registered and the app has finished starting.");

    public void Dispose() => _rsa?.Dispose();
}
