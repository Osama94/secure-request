using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using SecureRequest.AwsSecretsManager;
using Xunit;

namespace SecureRequest.AwsSecretsManager.Tests;

public class AwsSecretsManagerKeyStorageProviderTests
{
    private const string SecretId = "secure-request/rsa-private-key";

    private static (Mock<IAmazonSecretsManager> Client, AwsSecretsManagerKeyStorageProvider Provider) CreateSut(
        string secretId = SecretId)
    {
        var mockClient = new Mock<IAmazonSecretsManager>();
        var logger     = Mock.Of<ILogger<AwsSecretsManagerKeyStorageProvider>>();
        var provider   = new AwsSecretsManagerKeyStorageProvider(mockClient.Object, secretId, logger);
        return (mockClient, provider);
    }

    // ── LoadPrivateKeyAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenSecretExists_ReturnsDecodedBytes()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var originalBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var base64Value   = Convert.ToBase64String(originalBytes);

        mockClient
            .Setup(c => c.GetSecretValueAsync(
                It.Is<GetSecretValueRequest>(r => r.SecretId == SecretId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetSecretValueResponse { SecretString = base64Value });

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
            .Setup(c => c.GetSecretValueAsync(
                It.IsAny<GetSecretValueRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ResourceNotFoundException("Secret not found"));

        // Act
        var result = await provider.LoadPrivateKeyAsync();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenOtherExceptionOccurs_Rethrows()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.GetSecretValueAsync(
                It.IsAny<GetSecretValueRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidRequestException("Service error"));

        // Act
        var act = () => provider.LoadPrivateKeyAsync();

        // Assert
        await act.Should().ThrowAsync<InvalidRequestException>();
    }

    // ── StorePrivateKeyAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task StorePrivateKeyAsync_WhenSecretExists_CallsPutSecretValue()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[] { 0x01, 0x02, 0x03 };
        var expectedBase64  = Convert.ToBase64String(privateKeyBytes);

        mockClient
            .Setup(c => c.PutSecretValueAsync(
                It.Is<PutSecretValueRequest>(r =>
                    r.SecretId == SecretId && r.SecretString == expectedBase64),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PutSecretValueResponse());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert
        mockClient.Verify(
            c => c.PutSecretValueAsync(
                It.Is<PutSecretValueRequest>(r =>
                    r.SecretId == SecretId && r.SecretString == expectedBase64),
                It.IsAny<CancellationToken>()),
            Times.Once);

        // CreateSecretAsync must NOT be called when the secret already exists
        mockClient.Verify(
            c => c.CreateSecretAsync(It.IsAny<CreateSecretRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task StorePrivateKeyAsync_WhenSecretNotFound_CreatesSecretThenPutsValue()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[] { 0xAA, 0xBB };
        var expectedBase64  = Convert.ToBase64String(privateKeyBytes);

        // PutSecretValue throws ResourceNotFoundException on first call
        mockClient
            .Setup(c => c.PutSecretValueAsync(
                It.IsAny<PutSecretValueRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ResourceNotFoundException("Secret not found"));

        // CreateSecret succeeds
        mockClient
            .Setup(c => c.CreateSecretAsync(
                It.Is<CreateSecretRequest>(r =>
                    r.Name == SecretId && r.SecretString == expectedBase64),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new CreateSecretResponse());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert — CreateSecret was called once with the correct payload
        mockClient.Verify(
            c => c.CreateSecretAsync(
                It.Is<CreateSecretRequest>(r =>
                    r.Name == SecretId && r.SecretString == expectedBase64),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task StorePrivateKeyAsync_StoresExactBase64EncodingOfBytes()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[64];
        new Random(42).NextBytes(privateKeyBytes);
        var expectedBase64 = Convert.ToBase64String(privateKeyBytes);

        string? capturedSecretString = null;

        mockClient
            .Setup(c => c.PutSecretValueAsync(
                It.IsAny<PutSecretValueRequest>(),
                It.IsAny<CancellationToken>()))
            .Callback<PutSecretValueRequest, CancellationToken>(
                (req, _) => capturedSecretString = req.SecretString)
            .ReturnsAsync(new PutSecretValueResponse());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert
        capturedSecretString.Should().Be(expectedBase64);

        // Verify round-trip integrity
        var roundTrippedBytes = Convert.FromBase64String(capturedSecretString!);
        roundTrippedBytes.Should().BeEquivalentTo(privateKeyBytes);
    }

    [Fact]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        var act = () => new AwsSecretsManagerKeyStorageProvider(
            null!,
            SecretId,
            Mock.Of<ILogger<AwsSecretsManagerKeyStorageProvider>>());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("client");
    }

    [Fact]
    public void Constructor_WithNullSecretId_ThrowsArgumentNullException()
    {
        var act = () => new AwsSecretsManagerKeyStorageProvider(
            Mock.Of<IAmazonSecretsManager>(),
            null!,
            Mock.Of<ILogger<AwsSecretsManagerKeyStorageProvider>>());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("secretId");
    }
}
