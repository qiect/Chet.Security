using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

/// <summary>
/// MD5哈希算法单元测试
/// </summary>
public class MD5HelperTests
{
    /// <summary>
    /// 验证MD5对"hello"的已知哈希向量
    /// </summary>
    [Fact]
    public void ComputeString_KnownHelloVector()
    {
        Assert.Equal("5d41402abc4b2a76b9719d911017c592", MD5Helper.ComputeHash("hello"));
    }

    /// <summary>
    /// 验证MD5对额外已知向量的正确性
    /// </summary>
    [Theory]
    [InlineData("", "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData("abc", "900150983cd24fb0d6963f7d28e17f72")]
    [InlineData("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6")]
    public void ComputeString_AdditionalKnownVectors(string input, string expected)
    {
        Assert.Equal(expected, MD5Helper.ComputeHash(input));
    }

    /// <summary>
    /// 验证MD5十六进制输出长度为32个字符（128位）
    /// </summary>
    [Fact]
    public void ComputeHash_HasThirtyTwoHexChars()
    {
        Assert.Equal(32, MD5Helper.ComputeHash("data").Length);
    }

    /// <summary>
    /// 验证MD5的Base64输出与字节数组输出一致
    /// </summary>
    [Fact]
    public void ComputeHashBase64_MatchesBytes()
    {
        var hex = MD5Helper.ComputeHash("hello");
        var bytes = HexHelper.Decode(hex);
        Assert.Equal(Convert.ToBase64String(bytes), MD5Helper.ComputeHashBase64("hello"));
    }

    /// <summary>
    /// 验证MD5字节数组输出为16字节
    /// </summary>
    [Fact]
    public void ComputeHashBytes_ReturnsSixteenBytes()
    {
        Assert.Equal(16, MD5Helper.ComputeHashBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    /// <summary>
    /// 验证MD5计算结果具有确定性和输入敏感性
    /// </summary>
    [Fact]
    public void ComputeHash_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(MD5Helper.ComputeHash("a"), MD5Helper.ComputeHash("a"));
        Assert.NotEqual(MD5Helper.ComputeHash("a"), MD5Helper.ComputeHash("b"));
    }

    /// <summary>
    /// 验证文件哈希与字符串哈希结果一致
    /// </summary>
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

    /// <summary>
    /// 验证对不存在的文件进行哈希计算时抛出FileNotFoundException
    /// </summary>
    [Fact]
    public void ComputeFileHash_MissingFile_Throws()
    {
        Assert.Throws<FileNotFoundException>(() => MD5Helper.ComputeFileHash(Path.GetTempFileName() + ".missing"));
    }

    /// <summary>
    /// 验证对null字节数组进行MD5计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeHash_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MD5Helper.ComputeHash((byte[])null!));
    }

    /// <summary>
    /// 验证对null字符串进行MD5计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => MD5Helper.ComputeHash((string)null!));
    }

    /// <summary>
    /// 验证空字符串的MD5哈希为合法的密码学操作，返回已知向量
    /// </summary>
    [Fact]
    public void ComputeString_Empty_AllowedAndReturnsKnownVector()
    {
        // 空字符串摘要属于合法的密码学操作（与 BCL MD5.HashData(ReadOnlySpan<byte>.Empty) 行为一致）。
        Assert.Equal("d41d8cd98f00b204e9800998ecf8427e", MD5Helper.ComputeHash(string.Empty));
    }
}