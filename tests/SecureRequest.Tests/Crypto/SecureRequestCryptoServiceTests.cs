using SecureRequest.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace SecureRequest.Tests.Crypto;

public class SecureRequestCryptoServiceTests : IDisposable
{
    private readonly RsaKeyProvider _rsaKeyProvider = new();
    private readonly SecureRequestCryptoService _service;

    public SecureRequestCryptoServiceTests()
    {
        _rsaKeyProvider.GenerateAndExportPrivateKey();
        _service = new SecureRequestCryptoService(_rsaKeyProvider);
    }

    // ── DecryptSecretKey ──────────────────────────────────────────────────────

    [Fact]
    public void DecryptSecretKey_ValidSecret_Returns64Bytes()
    {
        var secret = new byte[64];
        Random.Shared.NextBytes(secret);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_rsaKeyProvider.GetPublicKeySpki(), out _);
        var encrypted = rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA256);

        var decrypted = _service.DecryptSecretKey(encrypted);
        decrypted.Should().BeEquivalentTo(secret);
        decrypted.Length.Should().Be(64);
    }

    [Fact]
    public void DecryptSecretKey_Wrong64BytePayload_ThrowsCryptographicException()
    {
        // Encrypt only 32 bytes — wrong secret size
        var shortSecret = new byte[32];
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_rsaKeyProvider.GetPublicKeySpki(), out _);
        var encrypted = rsa.Encrypt(shortSecret, RSAEncryptionPadding.OaepSHA256);

        var act = () => _service.DecryptSecretKey(encrypted);
        act.Should().Throw<CryptographicException>()
           .WithMessage("*64 bytes*");
    }

    [Fact]
    public void DecryptSecretKey_TamperedCiphertext_Throws()
    {
        var secret = new byte[64];
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_rsaKeyProvider.GetPublicKeySpki(), out _);
        var encrypted = rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA256);
        encrypted[5] ^= 0xFF;

        var act = () => _service.DecryptSecretKey(encrypted);
        act.Should().Throw<Exception>();
    }

    // ── Decrypt (AES-256-GCM) ─────────────────────────────────────────────────

    private static (byte[] encrypted, byte[] aesKey) EncryptPayload(string plaintext)
    {
        var aesKey    = new byte[32];
        var iv        = new byte[12];
        Random.Shared.NextBytes(aesKey);
        Random.Shared.NextBytes(iv);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext     = new byte[plaintextBytes.Length];
        var tag            = new byte[16];

        using var aes = new AesGcm(aesKey, 16);
        aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

        // Wire format: IV(12) + ciphertext + tag(16)
        var result = new byte[iv.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, result, iv.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, iv.Length + ciphertext.Length, tag.Length);

        return (result, aesKey);
    }

    [Fact]
    public void Decrypt_ValidPayload_ReturnsPlaintext()
    {
        const string original = "{\"name\":\"Osama\",\"role\":\"admin\"}";
        var (encrypted, aesKey) = EncryptPayload(original);

        var decrypted = _service.Decrypt(encrypted, aesKey);
        Encoding.UTF8.GetString(decrypted).Should().Be(original);
    }

    [Fact]
    public void Decrypt_WrongAesKey_ThrowsCryptographicException()
    {
        var (encrypted, _) = EncryptPayload("hello");
        var wrongKey = new byte[32];
        Random.Shared.NextBytes(wrongKey);

        var act = () => _service.Decrypt(encrypted, wrongKey);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_TamperedBody_ThrowsCryptographicException()
    {
        var (encrypted, aesKey) = EncryptPayload("hello world");
        encrypted[15] ^= 0xFF; // tamper ciphertext

        var act = () => _service.Decrypt(encrypted, aesKey);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_TooShortPayload_ThrowsCryptographicException()
    {
        var aesKey = new byte[32];
        var tooShort = new byte[10]; // less than IV(12) + tag(16)

        var act = () => _service.Decrypt(tooShort, aesKey);
        act.Should().Throw<CryptographicException>()
           .WithMessage("*too short*");
    }

    [Fact]
    public void Decrypt_WrongAesKeyLength_ThrowsArgumentException()
    {
        var (encrypted, _) = EncryptPayload("test");
        var badKey = new byte[16]; // AES-128 key, not AES-256

        var act = () => _service.Decrypt(encrypted, badKey);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*32 bytes*");
    }

    // ── ComputeBodyHash ───────────────────────────────────────────────────────

    [Fact]
    public void ComputeBodyHash_EmptyBytes_ReturnsKnownSha256Constant()
    {
        const string expectedEmptyHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        _service.ComputeBodyHash(Array.Empty<byte>()).Should().Be(expectedEmptyHash);
    }

    [Fact]
    public void ComputeBodyHash_KnownInput_ReturnsCorrectHex()
    {
        var input    = Encoding.UTF8.GetBytes("hello");
        var expected = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();

        _service.ComputeBodyHash(input).Should().Be(expected);
    }

    [Fact]
    public void ComputeBodyHash_DifferentInputs_ReturnDifferentHashes()
    {
        var hash1 = _service.ComputeBodyHash(Encoding.UTF8.GetBytes("aaa"));
        var hash2 = _service.ComputeBodyHash(Encoding.UTF8.GetBytes("bbb"));
        hash1.Should().NotBe(hash2);
    }

    // ── ComputeSignature ──────────────────────────────────────────────────────

    [Fact]
    public void ComputeSignature_SameInputs_ProduceSameSignature()
    {
        var hmacKey = new byte[32];
        Random.Shared.NextBytes(hmacKey);

        var sig1 = _service.ComputeSignature("POST", "/api/test", "", "1234567890", "nonce-abc", "bodyhash", hmacKey);
        var sig2 = _service.ComputeSignature("POST", "/api/test", "", "1234567890", "nonce-abc", "bodyhash", hmacKey);

        sig1.Should().Be(sig2);
    }

    [Fact]
    public void ComputeSignature_DifferentMethod_ProducesDifferentSignature()
    {
        var hmacKey = new byte[32];
        Random.Shared.NextBytes(hmacKey);

        var sig1 = _service.ComputeSignature("POST", "/api/test", "", "123", "nonce", "hash", hmacKey);
        var sig2 = _service.ComputeSignature("PUT",  "/api/test", "", "123", "nonce", "hash", hmacKey);

        sig1.Should().NotBe(sig2);
    }

    [Fact]
    public void ComputeSignature_DifferentKey_ProducesDifferentSignature()
    {
        var key1 = new byte[32];
        var key2 = new byte[32];
        Random.Shared.NextBytes(key1);
        Random.Shared.NextBytes(key2);

        var sig1 = _service.ComputeSignature("POST", "/api", "", "123", "nonce", "hash", key1);
        var sig2 = _service.ComputeSignature("POST", "/api", "", "123", "nonce", "hash", key2);

        sig1.Should().NotBe(sig2);
    }

    // ── ValidateSignature ─────────────────────────────────────────────────────

    [Fact]
    public void ValidateSignature_MatchingSignatures_ReturnsTrue()
    {
        var hmacKey = new byte[32];
        Random.Shared.NextBytes(hmacKey);
        var sig = _service.ComputeSignature("POST", "/api", "", "123", "nonce", "hash", hmacKey);

        _service.ValidateSignature(sig, sig).Should().BeTrue();
    }

    [Fact]
    public void ValidateSignature_DifferentSignatures_ReturnsFalse()
    {
        var key1 = new byte[32];
        var key2 = new byte[32];
        Random.Shared.NextBytes(key1);
        Random.Shared.NextBytes(key2);

        var sig1 = _service.ComputeSignature("POST", "/api", "", "123", "nonce", "hash", key1);
        var sig2 = _service.ComputeSignature("POST", "/api", "", "123", "nonce", "hash", key2);

        _service.ValidateSignature(sig1, sig2).Should().BeFalse();
    }

    [Fact]
    public void ValidateSignature_InvalidBase64_ReturnsFalse()
    {
        _service.ValidateSignature("valid-base64==", "not-base64!!!").Should().BeFalse();
    }

    public void Dispose() => _rsaKeyProvider.Dispose();
}
