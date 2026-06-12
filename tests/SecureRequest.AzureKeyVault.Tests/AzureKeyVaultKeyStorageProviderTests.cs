using Azure;
using Azure.Security.KeyVault.Secrets;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using SecureRequest.AzureKeyVault;
using Xunit;

namespace SecureRequest.AzureKeyVault.Tests;

public class AzureKeyVaultKeyStorageProviderTests
{
    private const string SecretName = "test-rsa-key";

    private static (Mock<SecretClient> Client, AzureKeyVaultKeyStorageProvider Provider) CreateSut()
    {
        var mockClient = new Mock<SecretClient>();
        var logger     = Mock.Of<ILogger<AzureKeyVaultKeyStorageProvider>>();
        var provider   = new AzureKeyVaultKeyStorageProvider(mockClient.Object, SecretName, logger);
        return (mockClient, provider);
    }

    // ── LoadPrivateKeyAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenSecretExists_ReturnsDecodedBytes()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var originalBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var base64Value   = Convert.ToBase64String(originalBytes);

        var secretProps = new SecretProperties(SecretName);
        var kvSecret    = SecretModelFactory.KeyVaultSecret(secretProps, base64Value);

        mockClient
            .Setup(c => c.GetSecretAsync(SecretName, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvSecret, Mock.Of<Response>()));

        // Act
        var result = await provider.LoadPrivateKeyAsync();

        // Assert
        result.Should().NotBeNull();
        result.Should().BeEquivalentTo(originalBytes);
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenSecretNotFound_ReturnsNull()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.GetSecretAsync(SecretName, null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(404, "Secret not found", "SecretNotFound", null));

        // Act
        var result = await provider.LoadPrivateKeyAsync();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenNon404Exception_Rethrows()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.GetSecretAsync(SecretName, null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(503, "Service unavailable"));

        // Act
        var act = () => provider.LoadPrivateKeyAsync();

        // Assert
        await act.Should().ThrowAsync<RequestFailedException>()
            .Where(ex => ex.Status == 503);
    }

    // ── StorePrivateKeyAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task StorePrivateKeyAsync_CallsSetSecretWithBase64EncodedKey()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[] { 0xAA, 0xBB, 0xCC };
        var expectedBase64  = Convert.ToBase64String(privateKeyBytes);

        var secretProps = new SecretProperties(SecretName);
        var kvSecret    = SecretModelFactory.KeyVaultSecret(secretProps, expectedBase64);

        mockClient
            .Setup(c => c.SetSecretAsync(SecretName, expectedBase64, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(kvSecret, Mock.Of<Response>()));

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert — SetSecretAsync was called exactly once with the correct Base64 value
        mockClient.Verify(
            c => c.SetSecretAsync(SecretName, expectedBase64, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task StorePrivateKeyAsync_WhenSetSecretThrows_Rethrows()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.SetSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(403, "Access denied"));

        // Act
        var act = () => provider.StorePrivateKeyAsync(new byte[] { 1, 2, 3 });

        // Assert
        await act.Should().ThrowAsync<RequestFailedException>()
            .Where(ex => ex.Status == 403);
    }
}
