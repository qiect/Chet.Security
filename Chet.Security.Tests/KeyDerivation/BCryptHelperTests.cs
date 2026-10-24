using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

public class BCryptHelperTests
{
    [Fact]
    public void HashPassword_ReturnsFormattedString()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.StartsWith("pbkdf2$1000$", hash);
        Assert.Equal(4, hash.Split('$').Length);
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.True(BCryptHelper.VerifyPassword("my-password", hash));
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.False(BCryptHelper.VerifyPassword("different-password", hash));
    }

    [Fact]
    public void HashPassword_DifferentCallsProduceDifferentHashes()
    {
        var a = BCryptHelper.HashPassword("my-password", iterations: 1000);
        var b = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.NotEqual(a, b);
        Assert.True(BCryptHelper.VerifyPassword("my-password", a));
        Assert.True(BCryptHelper.VerifyPassword("my-password", b));
    }

    [Fact]
    public void VerifyPassword_InvalidFormat_ReturnsFalse()
    {
        Assert.False(BCryptHelper.VerifyPassword("password", "not-a-valid-hash"));
    }

    [Fact]
    public void VerifyPassword_GarbageBodyButValidShape_ReturnsFalse()
    {
        Assert.False(BCryptHelper.VerifyPassword("password", "pbkdf2$1000$not-base64!!!$also-bad=="));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HashPassword_NullOrEmpty_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => BCryptHelper.HashPassword(password!));
    }

    [Fact]
    public void HashPassword_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BCryptHelper.HashPassword("password", 0));
    }
}
