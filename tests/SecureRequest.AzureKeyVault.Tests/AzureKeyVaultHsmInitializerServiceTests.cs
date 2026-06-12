using Azure;
using Azure.Security.KeyVault.Keys;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using SecureRequest.AzureKeyVault;
using SecureRequest.Crypto;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Xunit;

namespace SecureRequest.AzureKeyVault.Tests;

public class AzureKeyVaultHsmInitializerServiceTests
{
    // ── Reflection helper ─────────────────────────────────────────────────────
    // KeyVaultKeyModelFactory was added to the public Azure SDK surface in a later
    // release than the version pinned here. We use reflection to construct a
    // KeyVaultKey with the correct JsonWebKey — SDK-version-agnostic.

    private static KeyVaultKey CreateTestKeyVaultKey(string keyName, RSA rsa)
    {
        // Build a JsonWebKey from the RSA public key (public constructor available)
        var jwk = new JsonWebKey(rsa, includePrivateParameters: false);

        // KeyVaultKey has only internal constructors with required arguments.
        // RuntimeHelpers.GetUninitializedObject bypasses all constructors and allocates
        // a zero-initialised instance. We then set only the Key property that
        // AzureKeyVaultHsmInitializerService.StartAsync actually reads (response.Value.Key).
        var key = (KeyVaultKey)RuntimeHelpers.GetUninitializedObject(typeof(KeyVaultKey));

        typeof(KeyVaultKey)
            .GetProperty(nameof(KeyVaultKey.Key))!
            .SetValue(key, jwk);

        return key;
    }

    // ── Helper — build mock KeyClient ─────────────────────────────────────────

    private static (Mock<KeyClient> Client, RSAParameters PublicKeyParams) BuildMockKeyClient(
        string keyName, RSA rsa)
    {
        var kvKey      = CreateTestKeyVaultKey(keyName, rsa);
        var mockClient = new Mock<KeyClient>();
        mockClient
            .Setup(c => c.GetKeyAsync(keyName, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvKey, Mock.Of<Response>()));

        return (mockClient, rsa.ExportParameters(includePrivateParameters: false));
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_LoadsPublicKeyIntoRsaKeyProvider()
    {
        // Arrange
        const string keyName = "secure-request-rsa-key";

        using var rsa          = RSA.Create(2048);
        var (mockClient, _)    = BuildMockKeyClient(keyName, rsa);
        var rsaKeyProvider     = new RsaKeyProvider();
        var logger             = Mock.Of<ILogger<AzureKeyVaultHsmInitializerService>>();

        var service = new AzureKeyVaultHsmInitializerService(
            rsaKeyProvider, mockClient.Object, keyName, logger);

        // Act
        await service.StartAsync(CancellationToken.None);

        // Assert — public key is now loaded; GetPublicKeyBase64() should not throw
        var publicKeyBase64 = rsaKeyProvider.GetPublicKeyBase64();
        publicKeyBase64.Should().NotBeNullOrEmpty();

        // The loaded public key should round-trip back to the same RSA parameters
        var loadedSpki     = Convert.FromBase64String(publicKeyBase64);
        using var loadedRsa = RSA.Create();
        loadedRsa.ImportSubjectPublicKeyInfo(loadedSpki, out _);

        var originalParams = rsa.ExportParameters(includePrivateParameters: false);
        var loadedParams   = loadedRsa.ExportParameters(includePrivateParameters: false);

        loadedParams.Modulus.Should().BeEquivalentTo(originalParams.Modulus);
        loadedParams.Exponent.Should().BeEquivalentTo(originalParams.Exponent);
    }

    [Fact]
    public async Task StartAsync_CallsKeyClientWithCorrectKeyName()
    {
        // Arrange
        const string keyName = "my-custom-key";

        using var rsa       = RSA.Create(2048);
        var (mockClient, _) = BuildMockKeyClient(keyName, rsa);
        var rsaKeyProvider  = new RsaKeyProvider();
        var logger          = Mock.Of<ILogger<AzureKeyVaultHsmInitializerService>>();

        var service = new AzureKeyVaultHsmInitializerService(
            rsaKeyProvider, mockClient.Object, keyName, logger);

        // Act
        await service.StartAsync(CancellationToken.None);

        // Assert
        mockClient.Verify(
            c => c.GetKeyAsync(keyName, null, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task StartAsync_WhenKeyVaultThrows_PropagatesException()
    {
        // Arrange
        const string keyName = "missing-key";
        var mockClient       = new Mock<KeyClient>();
        var rsaKeyProvider   = new RsaKeyProvider();
        var logger           = Mock.Of<ILogger<AzureKeyVaultHsmInitializerService>>();

        mockClient
            .Setup(c => c.GetKeyAsync(keyName, null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(404, "Key not found", "KeyNotFound", null));

        var service = new AzureKeyVaultHsmInitializerService(
            rsaKeyProvider, mockClient.Object, keyName, logger);

        // Act
        var act = () => service.StartAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<RequestFailedException>();
    }

    [Fact]
    public async Task StopAsync_CompletesWithoutError()
    {
        // Arrange
        using var rsa       = RSA.Create(2048);
        var (mockClient, _) = BuildMockKeyClient("test-key", rsa);
        var rsaKeyProvider  = new RsaKeyProvider();
        var logger          = Mock.Of<ILogger<AzureKeyVaultHsmInitializerService>>();

        var service = new AzureKeyVaultHsmInitializerService(
            rsaKeyProvider, mockClient.Object, "test-key", logger);

        // Act / Assert — StopAsync must not throw
        var act = () => service.StopAsync(CancellationToken.None);
        await act.Should().NotThrowAsync();
    }
}
