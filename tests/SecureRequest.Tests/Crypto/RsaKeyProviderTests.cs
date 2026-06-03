using SecureRequest.Crypto;
using System.Security.Cryptography;

namespace SecureRequest.Tests.Crypto;

public class RsaKeyProviderTests : IDisposable
{
    private readonly RsaKeyProvider _provider = new();

    // ── GenerateAndExportPrivateKey ────────────────────────────────────────────

    [Fact]
    public void GenerateAndExportPrivateKey_ReturnsNonEmptyBytes()
    {
        var bytes = _provider.GenerateAndExportPrivateKey();
        bytes.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GenerateAndExportPrivateKey_ReturnsDifferentKeyEachTime()
    {
        var provider2 = new RsaKeyProvider();

        var key1 = _provider.GenerateAndExportPrivateKey();
        var key2 = provider2.GenerateAndExportPrivateKey();

        key1.Should().NotBeEquivalentTo(key2);

        provider2.Dispose();
    }

    // ── LoadFromPrivateKey ─────────────────────────────────────────────────────

    [Fact]
    public void LoadFromPrivateKey_AllowsDecryptionWithExportedPublicKey()
    {
        var privateKeyBytes = _provider.GenerateAndExportPrivateKey();

        // Load the key into a fresh provider (simulates server restart loading from cache)
        var provider2 = new RsaKeyProvider();
        provider2.LoadFromPrivateKey(privateKeyBytes);

        // Encrypt with provider2's public key, decrypt with _provider (same key pair)
        var plaintext  = new byte[] { 1, 2, 3, 4, 5 };
        using var rsa  = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(provider2.GetPublicKeySpki(), out _);
        var ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);

        var decrypted = provider2.Decrypt(ciphertext);
        decrypted.Should().BeEquivalentTo(plaintext);

        provider2.Dispose();
    }

    [Fact]
    public void LoadFromPrivateKey_InvalidBytes_Throws()
    {
        var act = () => _provider.LoadFromPrivateKey(new byte[] { 0, 1, 2, 3 });
        act.Should().Throw<Exception>();
    }

    // ── GetPublicKeyBase64 ────────────────────────────────────────────────────

    [Fact]
    public void GetPublicKeyBase64_BeforeInit_Throws()
    {
        var uninitialised = new RsaKeyProvider();
        var act = () => uninitialised.GetPublicKeyBase64();
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*not initialized*");
        uninitialised.Dispose();
    }

    [Fact]
    public void GetPublicKeyBase64_AfterGenerate_ReturnsValidBase64()
    {
        _provider.GenerateAndExportPrivateKey();
        var base64 = _provider.GetPublicKeyBase64();

        var act = () => Convert.FromBase64String(base64);
        act.Should().NotThrow();
        base64.Should().NotBeNullOrWhiteSpace();
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    [Fact]
    public void Decrypt_WithCorrectKey_ReturnsOriginalData()
    {
        _provider.GenerateAndExportPrivateKey();
        var data = new byte[32];
        Random.Shared.NextBytes(data);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_provider.GetPublicKeySpki(), out _);
        var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

        var decrypted = _provider.Decrypt(encrypted);
        decrypted.Should().BeEquivalentTo(data);
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        _provider.GenerateAndExportPrivateKey();
        var data = new byte[32];
        Random.Shared.NextBytes(data);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_provider.GetPublicKeySpki(), out _);
        var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        encrypted[10] ^= 0xFF; // tamper

        var act = () => _provider.Decrypt(encrypted);
        act.Should().Throw<CryptographicException>();
    }

    public void Dispose() => _provider.Dispose();
}
