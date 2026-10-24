using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

public class SM3HelperTests
{
    [Fact]
    public void ComputeHash_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SM3Helper.ComputeHash("abc").Length);
    }

    [Fact]
    public void ComputeHashBytes_ReturnsThirtyTwoBytes()
    {
        Assert.Equal(32, SM3Helper.ComputeHashBytes(System.Text.Encoding.UTF8.GetBytes("abc")).Length);
    }

    [Fact]
    public void ComputeHash_IsDeterministic()
    {
        Assert.Equal(SM3Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abc"));
    }

    [Fact]
    public void ComputeHash_IsInputSensitive()
    {
        Assert.NotEqual(SM3Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abd"));
    }

    [Fact]
    public void ComputeHash_DiffersFromMD5()
    {
        Assert.NotEqual(MD5Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abc"));
    }

    [Fact]
    public void ComputeHashBase64_MatchesBytes()
    {
        var hex = SM3Helper.ComputeHash("abc");
        var bytes = HexHelper.Decode(hex);
        Assert.Equal(Convert.ToBase64String(bytes), SM3Helper.ComputeHashBase64("abc"));
    }

    [Fact]
    public void ComputeHash_NonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(SM3Helper.ComputeHash("hello")));
    }

    [Fact]
    public void ComputeHash_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SM3Helper.ComputeHash((byte[])null!));
    }

    [Fact]
    public void ComputeString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SM3Helper.ComputeHash((string)null!));
    }
}
