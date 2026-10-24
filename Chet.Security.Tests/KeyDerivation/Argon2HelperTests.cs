using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

public class Argon2HelperTests
{
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        // Use light parameters (1MB memory, 1 iteration) to keep unit tests fast.
        var a = Argon2Helper.DeriveBytes("password", "fixed-salt", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password", "fixed-salt", iterations: 1, memoryKb: 1024);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, Argon2Helper.DeriveBytes("password", "salt", iterations: 1, memoryKb: 1024).Length);
    }

    [Fact]
    public void DeriveHex_HasSixtyFourChars()
    {
        Assert.Equal(64, Argon2Helper.DeriveHex("password", "salt", iterations: 1, memoryKb: 1024).Length);
    }

    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = Argon2Helper.DeriveBytes("password", "salt-1", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password", "salt-2", iterations: 1, memoryKb: 1024);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveBytes_DifferentPasswordProducesDifferentOutput()
    {
        var a = Argon2Helper.DeriveBytes("password-1", "salt", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password-2", "salt", iterations: 1, memoryKb: 1024);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveBase64_AndDeriveHex_AreConsistent()
    {
        var b64 = Argon2Helper.DeriveBase64("password", "salt", iterations: 1, memoryKb: 1024);
        var hex = Argon2Helper.DeriveHex("password", "salt", iterations: 1, memoryKb: 1024);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            Argon2Helper.DeriveBytes(password!, "salt", iterations: 1, memoryKb: 1024));
    }

    [Fact]
    public void DeriveBytes_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Helper.DeriveBytes("password", "salt", iterations: 0, memoryKb: 1024));
    }
}
