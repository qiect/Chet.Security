using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Random;

public class SecureRandomHelperTests
{
    [Fact]
    public void GenerateBytes_ReturnsRequestedLength()
    {
        Assert.Equal(32, SecureRandomHelper.GenerateBytes(32).Length);
    }

    [Fact]
    public void GenerateBytes_ZeroLength_ReturnsEmptyArray()
    {
        Assert.Empty(SecureRandomHelper.GenerateBytes(0));
    }

    [Fact]
    public void GenerateBytes_NegativeLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomHelper.GenerateBytes(-1));
    }

    [Fact]
    public void GenerateBytes_TwoCallsDiffer()
    {
        Assert.NotEqual(SecureRandomHelper.GenerateBytes(16), SecureRandomHelper.GenerateBytes(16));
    }

    [Fact]
    public void GenerateInt_WithRange_StaysWithinBounds()
    {
        for (var i = 0; i < 100; i++)
        {
            var v = SecureRandomHelper.GenerateInt(10, 20);
            Assert.True(v >= 10 && v < 20);
        }
    }

    [Fact]
    public void GenerateInt_RangeOfOne_AlwaysReturnsMin()
    {
        for (var i = 0; i < 20; i++)
            Assert.Equal(5, SecureRandomHelper.GenerateInt(5, 6));
    }

    [Fact]
    public void GenerateInt_InvalidRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomHelper.GenerateInt(10, 5));
    }

    [Fact]
    public void GenerateHex_LengthIsDoubleByteLength()
    {
        Assert.Equal(32, SecureRandomHelper.GenerateHex(16).Length);
    }

    [Fact]
    public void GenerateBase64_NonEmpty()
    {
        Assert.False(string.IsNullOrEmpty(SecureRandomHelper.GenerateBase64(16)));
    }

    [Fact]
    public void GeneratePassword_LengthMatchesRequest()
    {
        Assert.Equal(20, SecureRandomHelper.GeneratePassword(20).Length);
    }

    [Fact]
    public void GeneratePassword_WithoutSymbols_ContainsOnlyAlphanumerics()
    {
        var pw = SecureRandomHelper.GeneratePassword(40, includeSymbols: false);
        Assert.Equal(40, pw.Length);
        Assert.All(pw, c => Assert.True(char.IsLetterOrDigit(c)));
    }

    [Fact]
    public void GenerateUuid_IsParseableAsGuid()
    {
        Assert.True(Guid.TryParse(SecureRandomHelper.GenerateUuid(), out _));
    }

    [Fact]
    public void GenerateDouble_StaysWithinUnitHalfOpenInterval()
    {
        for (var i = 0; i < 100; i++)
        {
            var d = SecureRandomHelper.GenerateDouble();
            Assert.True(d >= 0.0 && d < 1.0);
        }
    }

    [Fact]
    public void Fill_PopulatesBufferWithNonZeroBytes()
    {
        var buffer = new byte[16];
        SecureRandomHelper.Fill(buffer);
        Assert.NotEqual(new byte[16], buffer);
    }

    [Fact]
    public void Fill_NullBuffer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SecureRandomHelper.Fill(null!));
    }
}
