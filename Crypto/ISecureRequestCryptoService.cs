namespace SecureRequest.Crypto;

/// <summary>
/// Cryptographic operations used by <see cref="Middleware.SecureRequestMiddleware"/>.
/// The default implementation uses RSA-OAEP-SHA256, AES-256-GCM, and HMAC-SHA256.
/// </summary>
public interface ISecureRequestCryptoService
{
    /// <summary>RSA-OAEP decrypts the per-request secret key (64 bytes: 32 AES + 32 HMAC).</summary>
    byte[] DecryptSecretKey(byte[] encryptedSecret);

    /// <summary>AES-256-GCM decrypts <paramref name="encryptedPayload"/> using <paramref name="aesKey"/>.</summary>
    byte[] Decrypt(byte[] encryptedPayload, byte[] aesKey);

    /// <summary>Returns the SHA-256 hex digest of <paramref name="body"/> (empty-body constant when input is empty).</summary>
    string ComputeBodyHash(byte[] body);

    /// <summary>
    /// Builds and HMAC-SHA256 signs the canonical string:
    /// <c>METHOD\nPATH\nQUERY\nTIMESTAMP\nNONCE\nBODY_HEX_HASH</c>
    /// </summary>
    string ComputeSignature(
        string method, string path, string query,
        string timestamp, string nonce, string bodyHexHash,
        byte[] hmacKey);

    /// <summary>Constant-time comparison of two Base64 signature strings.</summary>
    bool ValidateSignature(string expected, string actual);
}
