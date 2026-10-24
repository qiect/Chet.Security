using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

public class MD5HelperTests
{
    [Fact]
    public void ComputeString_KnownHelloVector()
    {
        Assert.Equal("5d41402abc4b2a76b9719d911017c592", MD5Helper.ComputeHash("hello"));
    }

    [Theory]
    [InlineData("", "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData("abc", "900150983cd24fb0d6963f7d28e17f72")]
    [InlineData("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6")]
    public void ComputeString_AdditionalKnownVectors(string input, string expected)
    {
        Assert.Equal(expected, MD5Helper.ComputeHash(input));
    }

    [Fact]
    public void ComputeHash_HasThirtyTwoHexChars()
    {
        Assert.Equal(32, MD5Helper.ComputeHash("data").Length);
    }

    [Fact]
    public void ComputeHashBase64_MatchesBytes()
    {
        var hex = MD5Helper.ComputeHash("hello");
        var bytes = HexHelper.Decode(hex);
        Assert.Equal(Convert.ToBase64String(bytes), MD5Helper.ComputeHashBase64("hello"));
    }

    [Fact]
    public void ComputeHashBytes_ReturnsSixteenBytes()
    {
        Assert.Equal(16, MD5Helper.ComputeHashBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    [Fact]
    public void ComputeHash_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(MD5Helper.ComputeHash("a"), MD5Helper.ComputeHash("a"));
        Assert.NotEqual(MD5Helper.ComputeHash("a"), MD5Helper.ComputeHash("b"));
    }

    [Fact]
    public void ComputeFileHash_MatchesStringHash()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "hello");
        try
        {
            Assert.Equal(MD5Helper.ComputeHash("hello"), MD5Helper.ComputeFileHash(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ComputeFileHash_MissingFile_Throws()
    {
        Assert.Throws<FileNotFoundException>(() => MD5Helper.ComputeFileHash(Path.GetTempFileName() + ".missing"));
    }

    [Fact]
    public void ComputeHash_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MD5Helper.ComputeHash((byte[])null!));
    }

    [Fact]
    public void ComputeString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => MD5Helper.ComputeHash((string)null!));
    }

    [Fact]
    public void ComputeString_Empty_AllowedAndReturnsKnownVector()
    {
        // 空字符串摘要属于合法的密码学操作（与 BCL MD5.HashData(ReadOnlySpan<byte>.Empty) 行为一致）。
        Assert.Equal("d41d8cd98f00b204e9800998ecf8427e", MD5Helper.ComputeHash(string.Empty));
    }
}
