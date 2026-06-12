using Azure;
using Azure.Security.KeyVault.Keys.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using SecureRequest.AzureKeyVault;
using System.Reflection;
using Xunit;

namespace SecureRequest.AzureKeyVault.Tests;

public class AzureKeyVaultDecryptProviderTests
{
    // ── Reflection helper ─────────────────────────────────────────────────────
    // CryptographyModelFactory was added to the public Azure SDK surface in a later
    // release than the version pinned here. We use reflection to construct and
    // populate DecryptResult instances — this is safe, SDK-version-agnostic, and
    // exercises the same production code paths.

    private static DecryptResult CreateDecryptResult(byte[] plaintext)
    {
        var result = (DecryptResult)Activator.CreateInstance(
            typeof(DecryptResult),
            bindingAttr: BindingFlags.NonPublic | BindingFlags.Instance,
            binder:      null,
            args:        Array.Empty<object>(),
            culture:     null)!;

        typeof(DecryptResult)
            .GetProperty(nameof(DecryptResult.Plaintext))!
            .SetValue(result, plaintext);

        typeof(DecryptResult)
            .GetProperty(nameof(DecryptResult.Algorithm))!
            .SetValue(result, EncryptionAlgorithm.RsaOaep256);

        return result;
    }

    // ── SUT factory ───────────────────────────────────────────────────────────

    private static (Mock<CryptographyClient> Client, AzureKeyVaultDecryptProvider Provider) CreateSut()
    {
        var mockClient = new Mock<CryptographyClient>();
        var logger     = Mock.Of<ILogger<AzureKeyVaultDecryptProvider>>();
        var provider   = new AzureKeyVaultDecryptProvider(mockClient.Object, logger);
        return (mockClient, provider);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DecryptAsync_DelegatesToKeyVaultAndReturnsPlaintext()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var ciphertext    = new byte[] { 0x10, 0x20, 0x30 };
        var plaintext     = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var decryptResult = CreateDecryptResult(plaintext);

        mockClient
            .Setup(c => c.DecryptAsync(
                EncryptionAlgorithm.RsaOaep256,
                ciphertext,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(decryptResult, Mock.Of<Response>()));

        // Act
        var result = await provider.DecryptAsync(ciphertext);

        // Assert
        result.Should().BeEquivalentTo(plaintext);
    }

    [Fact]
    public async Task DecryptAsync_UsesRsaOaep256Algorithm()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var decryptResult        = CreateDecryptResult(new byte[] { 1, 2, 3 });
        EncryptionAlgorithm capturedAlgorithm = default;

        mockClient
            .Setup(c => c.DecryptAsync(
                It.IsAny<EncryptionAlgorithm>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .Callback<EncryptionAlgorithm, byte[], CancellationToken>(
                (alg, _, _) => capturedAlgorithm = alg)
            .ReturnsAsync(Response.FromValue(decryptResult, Mock.Of<Response>()));

        // Act
        await provider.DecryptAsync(new byte[] { 0xFF });

        // Assert
        capturedAlgorithm.Should().Be(EncryptionAlgorithm.RsaOaep256);
    }

    [Fact]
    public async Task DecryptAsync_WhenKeyVaultThrows_Rethrows()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        mockClient
            .Setup(c => c.DecryptAsync(
                It.IsAny<EncryptionAlgorithm>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new RequestFailedException(403, "Access denied"));

        // Act
        var act = () => provider.DecryptAsync(new byte[] { 0x01 });

        // Assert
        await act.Should().ThrowAsync<RequestFailedException>();
    }

    [Fact]
    public async Task DecryptAsync_PassesCancellationTokenToKeyVault()
    {
        // Arrange
        var (mockClient, provider) = CreateSut();

        var cts           = new CancellationTokenSource();
        var decryptResult = CreateDecryptResult(new byte[] { 1 });
        CancellationToken capturedToken = default;

        mockClient
            .Setup(c => c.DecryptAsync(
                It.IsAny<EncryptionAlgorithm>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .Callback<EncryptionAlgorithm, byte[], CancellationToken>(
                (_, _, ct) => capturedToken = ct)
            .ReturnsAsync(Response.FromValue(decryptResult, Mock.Of<Response>()));

        // Act
        await provider.DecryptAsync(new byte[] { 0x01 }, cts.Token);

        // Assert
        capturedToken.Should().Be(cts.Token);
    }
}
