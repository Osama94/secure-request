namespace SecureRequest.Crypto;

/// <summary>
/// Provides the server's RSA public key so it can be exposed to clients.
/// Implement or resolve this to serve the key from a controller / minimal-API endpoint.
/// </summary>
public interface IRsaPublicKeyProvider
{
    /// <summary>Returns the RSA public key encoded as a Base64 SPKI (SubjectPublicKeyInfo) string.</summary>
    string GetPublicKeyBase64();
}
