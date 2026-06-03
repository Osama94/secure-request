using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureRequest.KeyStorage;

namespace SecureRequest.Tests.KeyStorage;

public class DistributedCacheKeyStorageProviderTests
{
    private static IDistributedCache CreateCache()
    {
        var opts = MsOptions.Create(new MemoryDistributedCacheOptions());
        return new MemoryDistributedCache(opts);
    }

    private static DistributedCacheKeyStorageProvider CreateProvider(IDistributedCache cache)
        => new(cache, NullLogger<DistributedCacheKeyStorageProvider>.Instance);

    // ── LoadPrivateKeyAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenCacheEmpty_ReturnsNull()
    {
        var provider = CreateProvider(CreateCache());
        var result   = await provider.LoadPrivateKeyAsync();
        result.Should().BeNull();
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_AfterStore_ReturnsSameBytes()
    {
        var cache    = CreateCache();
        var provider = CreateProvider(cache);

        var key = new byte[64];
        Random.Shared.NextBytes(key);

        await provider.StorePrivateKeyAsync(key);
        var loaded = await provider.LoadPrivateKeyAsync();

        loaded.Should().BeEquivalentTo(key);
    }

    // ── StorePrivateKeyAsync ──────────────────────────────────────────────────

    [Fact]
    public async Task StorePrivateKeyAsync_OverwritesPreviousKey()
    {
        var cache    = CreateCache();
        var provider = CreateProvider(cache);

        var key1 = new byte[64];
        var key2 = new byte[64];
        Random.Shared.NextBytes(key1);
        Random.Shared.NextBytes(key2);

        await provider.StorePrivateKeyAsync(key1);
        await provider.StorePrivateKeyAsync(key2);

        var loaded = await provider.LoadPrivateKeyAsync();
        loaded.Should().BeEquivalentTo(key2);
        loaded.Should().NotBeEquivalentTo(key1);
    }

    [Fact]
    public async Task StoreAndLoad_RoundTrip_PreservesExactBytes()
    {
        var provider = CreateProvider(CreateCache());
        var expected = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        await provider.StorePrivateKeyAsync(expected);
        var actual = await provider.LoadPrivateKeyAsync();

        actual.Should().BeEquivalentTo(expected);
    }
}
