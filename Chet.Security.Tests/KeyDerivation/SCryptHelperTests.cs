using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

public class SCryptHelperTests
{
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        // Use small N for speed while still exercising the SCrypt pipeline.
        var a = SCryptHelper.DeriveBytes("password", "fixed-salt", n: 1024, r: 8, p: 1);
        var b = SCryptHelper.DeriveBytes("password", "fixed-salt", n: 1024, r: 8, p: 1);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, SCryptHelper.DeriveBytes("password", "salt", n: 1024).Length);
    }

    [Fact]
    public void DeriveBytes_CustomLengthRespected()
    {
        Assert.Equal(64, SCryptHelper.DeriveBytes("password", "salt", n: 1024, derivedLength: 64).Length);
    }

    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = SCryptHelper.DeriveBytes("password", "salt-1", n: 1024);
        var b = SCryptHelper.DeriveBytes("password", "salt-2", n: 1024);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveBase64_AndDeriveHex_AreDeterministicAndConsistent()
    {
        var b64 = SCryptHelper.DeriveBase64("password", "salt", n: 1024);
        var hex = SCryptHelper.DeriveHex("password", "salt", n: 1024);
        Assert.Equal(b64, SCryptHelper.DeriveBase64("password", "salt", n: 1024));
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => SCryptHelper.DeriveBytes(password!, "salt", n: 1024));
    }

    [Fact]
    public void DeriveBytes_NonPowerOfTwoN_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SCryptHelper.DeriveBytes("password", "salt", n: 100));
    }
}
