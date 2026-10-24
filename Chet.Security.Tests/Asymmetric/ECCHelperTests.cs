using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

public class ECCHelperTests
{
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = ECCHelper.Sign(data, priv);
        Assert.True(ECCHelper.Verify(data, signature, pub));
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        var signature = ECCHelper.Sign("original-data", priv);
        Assert.False(ECCHelper.Verify("tampered-data", signature, pub));
    }

    [Fact]
    public void DeriveSharedSecret_ReturnsThirtyTwoBytes()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var shared = ECCHelper.DeriveSharedSecret(privA, pubA);
        Assert.Equal(32, shared.Length);
    }

    [Fact]
    public void DeriveSharedSecret_IsSymmetricBetweenTwoKeyPairs()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var (pubB, privB) = ECCHelper.GenerateKeyPair();

        var aliceShared = ECCHelper.DeriveSharedSecret(privA, pubB);
        var bobShared = ECCHelper.DeriveSharedSecret(privB, pubA);

        Assert.Equal(aliceShared, bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_DiffersForDifferentKeyPairs()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var (pubB, privB) = ECCHelper.GenerateKeyPair();
        var (pubC, _) = ECCHelper.GenerateKeyPair();

        var withB = ECCHelper.DeriveSharedSecret(privA, pubB);
        var withC = ECCHelper.DeriveSharedSecret(privA, pubC);
        Assert.NotEqual(withB, withC);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Sign_NullOrEmptyData_Throws(string? data)
    {
        var (_, priv) = ECCHelper.GenerateKeyPair();
        Assert.ThrowsAny<ArgumentException>(() => ECCHelper.Sign(data!, priv));
    }
}
