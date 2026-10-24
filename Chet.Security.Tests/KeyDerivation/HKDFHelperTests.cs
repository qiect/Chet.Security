using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

public class HKDFHelperTests
{
    [Fact]
    public void DeriveKey_IsDeterministic()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt", "info");
        var b = HKDFHelper.DeriveKey("ikm", "salt", "info");
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveKey_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, HKDFHelper.DeriveKey("ikm", "salt", "info").Length);
    }

    [Fact]
    public void DeriveKey_CustomLengthRespected()
    {
        Assert.Equal(64, HKDFHelper.DeriveKey("ikm", "salt", "info", 64).Length);
    }

    [Fact]
    public void DeriveKey_DifferentSaltProducesDifferentOutput()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt-1", "info");
        var b = HKDFHelper.DeriveKey("ikm", "salt-2", "info");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveKey_DifferentInfoProducesDifferentOutput()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt", "info-1");
        var b = HKDFHelper.DeriveKey("ikm", "salt", "info-2");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveKeyBase64_AndDeriveKeyHex_AreConsistent()
    {
        var b64 = HKDFHelper.DeriveKeyBase64("ikm", "salt", "info");
        var hex = HKDFHelper.DeriveKeyHex("ikm", "salt", "info");
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    [Fact]
    public void DeriveKey_NullIkm_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HKDFHelper.DeriveKey((byte[])null!, Array.Empty<byte>(), Array.Empty<byte>()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveKeyString_NullOrEmptyIkm_Throws(string? ikm)
    {
        Assert.ThrowsAny<ArgumentException>(() => HKDFHelper.DeriveKey(ikm!, "salt", "info"));
    }

    [Fact]
    public void DeriveKey_NonPositiveLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HKDFHelper.DeriveKey("ikm", "salt", "info", 0));
    }
}
