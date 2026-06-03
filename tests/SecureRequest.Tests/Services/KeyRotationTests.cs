using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureRequest.Crypto;
using SecureRequest.KeyStorage;
using SecureRequest.Services;

namespace SecureRequest.Tests.Services;

public class KeyRotationTests : IDisposable
{
    private readonly RsaKeyProvider _rsaKeyProvider = new();
    private readonly DistributedCacheKeyStorageProvider _storageProvider;
    private readonly SecureRequestKeyRotationService _rotationService;

    public KeyRotationTests()
    {
        var cache = new MemoryDistributedCache(MsOptions.Create(new MemoryDistributedCacheOptions()));
        _storageProvider  = new DistributedCacheKeyStorageProvider(cache, NullLogger<DistributedCacheKeyStorageProvider>.Instance);
        _rotationService  = new SecureRequestKeyRotationService(
            _rsaKeyProvider,
            _storageProvider,
            NullLogger<SecureRequestKeyRotationService>.Instance);

        _rsaKeyProvider.GenerateAndExportPrivateKey();
    }

    [Fact]
    public async Task RotateKeyAsync_ReturnsNewPublicKeyBase64()
    {
        var result = await _rotationService.RotateKeyAsync();
        result.Should().NotBeNullOrWhiteSpace();
        var act = () => Convert.FromBase64String(result);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task RotateKeyAsync_ChangesPublicKey()
    {
        var keyBefore = _rsaKeyProvider.GetPublicKeyBase64();
        await _rotationService.RotateKeyAsync();
        var keyAfter  = _rsaKeyProvider.GetPublicKeyBase64();

        keyAfter.Should().NotBe(keyBefore);
    }

    [Fact]
    public async Task RotateKeyAsync_PersistsNewKeyToStorage()
    {
        await _rotationService.RotateKeyAsync();

        var storedBytes = await _storageProvider.LoadPrivateKeyAsync();
        storedBytes.Should().NotBeNull();
        storedBytes!.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task RotateKeyAsync_StoredKeyMatchesActiveKey()
    {
        await _rotationService.RotateKeyAsync();

        var storedBytes   = await _storageProvider.LoadPrivateKeyAsync();
        var freshProvider = new RsaKeyProvider();
        freshProvider.LoadFromPrivateKey(storedBytes!);

        freshProvider.GetPublicKeyBase64().Should().Be(_rsaKeyProvider.GetPublicKeyBase64());

        freshProvider.Dispose();
    }

    [Fact]
    public async Task RotateKeyAsync_MultipleTimes_EachTimeProducesNewKey()
    {
        var keys = new HashSet<string>();
        for (int i = 0; i < 3; i++)
        {
            var key = await _rotationService.RotateKeyAsync();
            keys.Add(key);
        }
        keys.Should().HaveCount(3, "each rotation must produce a unique key pair");
    }

    public void Dispose() => _rsaKeyProvider.Dispose();
}
