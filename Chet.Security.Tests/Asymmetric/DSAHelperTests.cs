using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

public class DSAHelperTests
{
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    [Fact]
    public void GenerateKeyPair_InvalidKeySize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DSAHelper.GenerateKeyPair(2049));
    }

    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = DSAHelper.Sign(data, priv);
        Assert.True(DSAHelper.Verify(data, signature, pub));
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var signature = DSAHelper.Sign("original-data", priv);
        Assert.False(DSAHelper.Verify("tampered-data", signature, pub));
    }

    [Fact]
    public void Sign_DifferentInvocationsProduceValidButPotentiallyDifferentSignatures()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var data = "some-data";
        var sig1 = DSAHelper.Sign(data, priv);
        var sig2 = DSAHelper.Sign(data, priv);
        // Both must verify.
        Assert.True(DSAHelper.Verify(data, sig1, pub));
        Assert.True(DSAHelper.Verify(data, sig2, pub));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Sign_NullOrEmptyData_Throws(string? data)
    {
        var (_, priv) = DSAHelper.GenerateKeyPair();
        Assert.ThrowsAny<ArgumentException>(() => DSAHelper.Sign(data!, priv));
    }
}
