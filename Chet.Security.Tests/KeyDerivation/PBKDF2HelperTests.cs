using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

public class PBKDF2HelperTests
{
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        var a = PBKDF2Helper.DeriveBytes("password", "fixed-salt", iterations: 1000);
        var b = PBKDF2Helper.DeriveBytes("password", "fixed-salt", iterations: 1000);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, PBKDF2Helper.DeriveBytes("password", "salt").Length);
    }

    [Fact]
    public void DeriveBytes_CustomLengthRespected()
    {
        Assert.Equal(64, PBKDF2Helper.DeriveBytes("password", "salt", 100, 64).Length);
    }

    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = PBKDF2Helper.DeriveBytes("password", "salt-1");
        var b = PBKDF2Helper.DeriveBytes("password", "salt-2");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveBase64_AndDeriveHex_AreDeterministicAndConsistent()
    {
        var b64 = PBKDF2Helper.DeriveBase64("password", "salt", 1000);
        var hex = PBKDF2Helper.DeriveHex("password", "salt", 1000);
        Assert.Equal(b64, PBKDF2Helper.DeriveBase64("password", "salt", 1000));
        Assert.Equal(hex, PBKDF2Helper.DeriveHex("password", "salt", 1000));
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    [Fact]
    public void GenerateSalt_DefaultLengthIsSixteen()
    {
        Assert.Equal(16, PBKDF2Helper.GenerateSalt().Length);
    }

    [Fact]
    public void GenerateSalt_CustomLengthRespected()
    {
        Assert.Equal(32, PBKDF2Helper.GenerateSalt(32).Length);
    }

    [Fact]
    public void GenerateSalt_DifferentCallsDiffer()
    {
        Assert.NotEqual(PBKDF2Helper.GenerateSalt(), PBKDF2Helper.GenerateSalt());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => PBKDF2Helper.DeriveBytes(password!, "salt"));
    }

    [Fact]
    public void DeriveBytes_NullSalt_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => PBKDF2Helper.DeriveBytes("password", (byte[])null!));
    }

    [Fact]
    public void DeriveBytes_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PBKDF2Helper.DeriveBytes("password", "salt", 0));
    }
}
