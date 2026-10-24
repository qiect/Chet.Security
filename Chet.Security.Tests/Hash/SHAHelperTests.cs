using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

public class SHAHelperTests
{
    [Fact]
    public void ComputeSHA1_Hello_KnownVector()
    {
        Assert.Equal("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", SHAHelper.ComputeSHA1("hello"));
    }

    [Fact]
    public void ComputeSHA256_Hello_KnownVector()
    {
        Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            SHAHelper.ComputeSHA256("hello"));
    }

    [Fact]
    public void ComputeSHA256_Empty_KnownVector()
    {
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SHAHelper.ComputeSHA256(""));
    }

    [Fact]
    public void ComputeSHA1_HasFortyHexChars()
    {
        Assert.Equal(40, SHAHelper.ComputeSHA1("data").Length);
    }

    [Fact]
    public void ComputeSHA256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SHAHelper.ComputeSHA256("data").Length);
    }

    [Fact]
    public void ComputeSHA384_HasNinetySixHexChars()
    {
        Assert.Equal(96, SHAHelper.ComputeSHA384("hello").Length);
    }

    [Fact]
    public void ComputeSHA512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, SHAHelper.ComputeSHA512("hello").Length);
    }

    [Fact]
    public void ComputeSHA3_256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SHAHelper.ComputeSHA3_256("hello").Length);
    }

    [Fact]
    public void ComputeSHA3_384_HasNinetySixHexChars()
    {
        Assert.Equal(96, SHAHelper.ComputeSHA3_384("hello").Length);
    }

    [Fact]
    public void ComputeSHA3_512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, SHAHelper.ComputeSHA3_512("hello").Length);
    }

    [Fact]
    public void SHA3_256_DiffersFromSHA256()
    {
        Assert.NotEqual(SHAHelper.ComputeSHA256("hello"), SHAHelper.ComputeSHA3_256("hello"));
    }

    [Fact]
    public void SHA512_DiffersFromSHA256()
    {
        Assert.NotEqual(SHAHelper.ComputeSHA256("hello"), SHAHelper.ComputeSHA512("hello"));
    }

    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(SHAHelper.ComputeSHA256("a"), SHAHelper.ComputeSHA256("a"));
        Assert.NotEqual(SHAHelper.ComputeSHA256("a"), SHAHelper.ComputeSHA256("b"));
    }

    [Fact]
    public void ComputeFileSHA256_MatchesStringHash()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "hello");
        try
        {
            Assert.Equal(SHAHelper.ComputeSHA256("hello"), SHAHelper.ComputeFileSHA256(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ComputeSHA256_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SHAHelper.ComputeSHA256((byte[])null!));
    }

    [Fact]
    public void ComputeSHA256_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SHAHelper.ComputeSHA256((string)null!));
    }
}
