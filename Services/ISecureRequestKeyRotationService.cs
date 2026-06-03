namespace SecureRequest.Services;

/// <summary>
/// Provides RSA key pair rotation for the secure-request pipeline.
///
/// Key rotation flow:
///   1. Generates a new RSA-2048 key pair.
///   2. Persists the new private key via <see cref="KeyStorage.IRsaKeyStorageProvider"/>
///      (overwrites the old key in Redis / Azure Key Vault / AWS KMS / etc.).
///   3. Loads the new key pair into memory — all future requests use the new keys immediately.
///   4. Clients that cached the old public key will receive a 422 on their next request,
///      automatically clear their cache, re-fetch the new public key, and retry.
///      (This is handled by the built-in 422 auto-retry in the frontend interceptor.)
///
/// When to rotate:
///   - On a regular schedule (e.g. every 90 days via a cron job or scheduled task)
///   - After a suspected key compromise
///   - After deploying a new environment
/// </summary>
public interface ISecureRequestKeyRotationService
{
    /// <summary>
    /// Rotates the RSA key pair: generates a new pair, persists it, and activates it immediately.
    /// Returns the new public key as Base64 so callers can log or audit it.
    /// </summary>
    Task<string> RotateKeyAsync(CancellationToken cancellationToken = default);
}
