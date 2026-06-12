using FluentAssertions;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Moq;
using SecureRequest.GcpSecretManager;
using Xunit;

namespace SecureRequest.GcpSecretManager.Tests;

public class GcpSecretManagerKeyStorageProviderTests
{
    private const string ProjectId = "my-test-project";
    private const string SecretId  = "secure-request-rsa-private-key";

    private static (Mock<SecretManagerServiceClient> Client, GcpSecretManagerKeyStorageProvider Provider) CreateSut(
        string projectId = ProjectId, string secretId = SecretId)
    {
        var mockClient = new Mock<SecretManagerServiceClient>();
        var logger     = Mock.Of<ILogger<GcpSecretManagerKeyStorageProvider>>();
        var provider   = new GcpSecretManagerKeyStorageProvider(
            mockClient.Object, projectId, secretId, logger);
        return (mockClient, provider);
    }

    private static RpcException NotFoundRpcException()
        => new(new Status(StatusCode.NotFound, "Secret not found"));

    // ── LoadPrivateKeyAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenSecretVersionExists_ReturnsDecodedBytes()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var originalBytes = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        var base64Value   = Convert.ToBase64String(originalBytes);

        var secretVersionName = new SecretVersionName(ProjectId, SecretId, "latest");
        var response = new AccessSecretVersionResponse
        {
            Payload = new SecretPayload
            {
                Data = ByteString.CopyFromUtf8(base64Value)
            }
        };

        mockClient
            .Setup(c => c.AccessSecretVersionAsync(
                It.Is<SecretVersionName>(n =>
                    n.ProjectId == ProjectId &&
                    n.SecretId  == SecretId  &&
                    n.SecretVersionId == "latest"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);

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
            .Setup(c => c.AccessSecretVersionAsync(
                It.IsAny<SecretVersionName>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(NotFoundRpcException());

        // Act
        var result = await provider.LoadPrivateKeyAsync();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_WhenOtherRpcException_Rethrows()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.AccessSecretVersionAsync(
                It.IsAny<SecretVersionName>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RpcException(new Status(StatusCode.PermissionDenied, "Access denied")));

        // Act
        var act = () => provider.LoadPrivateKeyAsync();

        // Assert
        await act.Should().ThrowAsync<RpcException>()
            .Where(ex => ex.StatusCode == StatusCode.PermissionDenied);
    }

    // ── StorePrivateKeyAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task StorePrivateKeyAsync_WhenSecretExists_AddsNewVersion()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[] { 0x01, 0x02, 0x03 };
        var expectedBase64  = Convert.ToBase64String(privateKeyBytes);

        mockClient
            .Setup(c => c.AddSecretVersionAsync(
                It.Is<AddSecretVersionRequest>(r =>
                    r.Parent == $"projects/{ProjectId}/secrets/{SecretId}" &&
                    r.Payload.Data.ToStringUtf8() == expectedBase64),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SecretVersion());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert
        mockClient.Verify(
            c => c.AddSecretVersionAsync(
                It.Is<AddSecretVersionRequest>(r =>
                    r.Parent == $"projects/{ProjectId}/secrets/{SecretId}"),
                It.IsAny<CancellationToken>()),
            Times.Once);

        // CreateSecret must NOT be called when secret already exists
        mockClient.Verify(
            c => c.CreateSecretAsync(
                It.IsAny<CreateSecretRequest>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task StorePrivateKeyAsync_WhenSecretNotFound_CreatesSecretThenAddsVersion()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[] { 0xDE, 0xAD };
        var expectedBase64  = Convert.ToBase64String(privateKeyBytes);

        // First call to AddSecretVersionAsync throws NotFound
        mockClient
            .SetupSequence(c => c.AddSecretVersionAsync(
                It.IsAny<AddSecretVersionRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(NotFoundRpcException())  // first call — secret doesn't exist
            .ReturnsAsync(new SecretVersion());   // second call — after secret is created

        mockClient
            .Setup(c => c.CreateSecretAsync(
                It.Is<CreateSecretRequest>(r =>
                    r.Parent   == $"projects/{ProjectId}" &&
                    r.SecretId == SecretId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Secret());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert
        mockClient.Verify(
            c => c.CreateSecretAsync(
                It.Is<CreateSecretRequest>(r =>
                    r.Parent   == $"projects/{ProjectId}" &&
                    r.SecretId == SecretId),
                It.IsAny<CancellationToken>()),
            Times.Once);

        mockClient.Verify(
            c => c.AddSecretVersionAsync(
                It.IsAny<AddSecretVersionRequest>(),
                It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task StorePrivateKeyAsync_PayloadIsBase64EncodedBytes()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var privateKeyBytes = new byte[32];
        new Random(99).NextBytes(privateKeyBytes);
        var expectedBase64 = Convert.ToBase64String(privateKeyBytes);

        string? capturedPayload = null;

        mockClient
            .Setup(c => c.AddSecretVersionAsync(
                It.IsAny<AddSecretVersionRequest>(),
                It.IsAny<CancellationToken>()))
            .Callback<AddSecretVersionRequest, CancellationToken>(
                (req, _) => capturedPayload = req.Payload.Data.ToStringUtf8())
            .ReturnsAsync(new SecretVersion());

        // Act
        await provider.StorePrivateKeyAsync(privateKeyBytes);

        // Assert
        capturedPayload.Should().Be(expectedBase64);

        // Verify round-trip integrity
        var roundTripped = Convert.FromBase64String(capturedPayload!);
        roundTripped.Should().BeEquivalentTo(privateKeyBytes);
    }

    [Fact]
    public async Task LoadPrivateKeyAsync_UsesLatestSecretVersion()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        SecretVersionName? capturedName = null;

        mockClient
            .Setup(c => c.AccessSecretVersionAsync(
                It.IsAny<SecretVersionName>(),
                It.IsAny<CancellationToken>()))
            .Callback<SecretVersionName, CancellationToken>(
                (name, _) => capturedName = name)
            .ReturnsAsync(new AccessSecretVersionResponse
            {
                Payload = new SecretPayload
                {
                    Data = ByteString.CopyFromUtf8(Convert.ToBase64String(new byte[] { 1 }))
                }
            });

        // Act
        await provider.LoadPrivateKeyAsync();

        // Assert — must request the "latest" version
        capturedName.Should().NotBeNull();
        capturedName!.SecretVersionId.Should().Be("latest");
        capturedName.ProjectId.Should().Be(ProjectId);
        capturedName.SecretId.Should().Be(SecretId);
    }

    [Fact]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        var act = () => new GcpSecretManagerKeyStorageProvider(
            null!,
            ProjectId,
            SecretId,
            Mock.Of<ILogger<GcpSecretManagerKeyStorageProvider>>());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("client");
    }

    [Fact]
    public void Constructor_WithNullProjectId_ThrowsArgumentNullException()
    {
        var act = () => new GcpSecretManagerKeyStorageProvider(
            Mock.Of<SecretManagerServiceClient>(),
            null!,
            SecretId,
            Mock.Of<ILogger<GcpSecretManagerKeyStorageProvider>>());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("projectId");
    }
}
