using System.Security.Cryptography;

namespace SecureRequest.Crypto;

/// <summary>
/// Singleton that holds the server's RSA-2048 key pair in memory.
///
/// Lifecycle:
///   - On first startup <see cref="Services.RsaKeyInitializerService"/> checks the distributed cache.
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
    /// Loads only the public key from a DER-encoded SubjectPublicKeyInfo (SPKI) byte array.
    /// Use this in HSM mode where the private key never leaves a cloud KMS —
    /// the public key is fetched from the KMS and loaded here so that
    /// <see cref="GetPublicKeyBase64"/> and <see cref="GetPublicKeySpki"/> work correctly.
    ///
    /// ⚠️ After calling this method <see cref="Decrypt"/> will throw because the private
    /// key is not available locally. All decryption must go through
    /// <see cref="IRsaDecryptProvider.DecryptAsync"/> (e.g. <c>AzureKeyVaultDecryptProvider</c>).
    /// </summary>
    public void LoadPublicKeyOnly(byte[] spkiPublicKey)
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spkiPublicKey, out _);
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

    // ── Used by SecureRequestCryptoService ───────────────────────────────────

    /// <summary>Exports the public key as a DER-encoded SubjectPublicKeyInfo (SPKI) byte array.</summary>
    public byte[] GetPublicKeySpki() => GetRsa().ExportSubjectPublicKeyInfo();

    /// <summary>RSA-OAEP-SHA256 decrypts <paramref name="ciphertext"/> using the private key.</summary>
    public byte[] Decrypt(byte[] ciphertext) =>
        GetRsa().Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RSA GetRsa() =>
        _rsa ?? throw new InvalidOperationException(
            "[SecureRequest] RSA key pair is not initialized yet. " +
            "Ensure AddSecureRequest() is registered and the app has finished starting.");

    /// <inheritdoc/>
    public void Dispose() => _rsa?.Dispose();
}
