using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

/// <summary>
/// SHA系列哈希算法单元测试（包含SHA-1、SHA-256、SHA-384、SHA-512、SHA3-256、SHA3-384、SHA3-512）
/// </summary>
public class SHAHelperTests
{
    /// <summary>
    /// 验证SHA-1对"hello"的已知哈希向量
    /// </summary>
    [Fact]
    public void ComputeSHA1_Hello_KnownVector()
    {
        Assert.Equal("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", SHAHelper.ComputeSHA1("hello"));
    }

    /// <summary>
    /// 验证SHA-256对"hello"的已知哈希向量
    /// </summary>
    [Fact]
    public void ComputeSHA256_Hello_KnownVector()
    {
        Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            SHAHelper.ComputeSHA256("hello"));
    }

    /// <summary>
    /// 验证SHA-256对空字符串的已知哈希向量
    /// </summary>
    [Fact]
    public void ComputeSHA256_Empty_KnownVector()
    {
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SHAHelper.ComputeSHA256(""));
    }

    /// <summary>
    /// 验证SHA-1的十六进制输出长度为40个字符（160位）
    /// </summary>
    [Fact]
    public void ComputeSHA1_HasFortyHexChars()
    {
        Assert.Equal(40, SHAHelper.ComputeSHA1("data").Length);
    }

    /// <summary>
    /// 验证SHA-256的十六进制输出长度为64个字符（256位）
    /// </summary>
    [Fact]
    public void ComputeSHA256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SHAHelper.ComputeSHA256("data").Length);
    }

    /// <summary>
    /// 验证SHA-384的十六进制输出长度为96个字符（384位）
    /// </summary>
    [Fact]
    public void ComputeSHA384_HasNinetySixHexChars()
    {
        Assert.Equal(96, SHAHelper.ComputeSHA384("hello").Length);
    }

    /// <summary>
    /// 验证SHA-512的十六进制输出长度为128个字符（512位）
    /// </summary>
    [Fact]
    public void ComputeSHA512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, SHAHelper.ComputeSHA512("hello").Length);
    }

    /// <summary>
    /// 验证SHA3-256的十六进制输出长度为64个字符（256位）
    /// </summary>
    [Fact]
    public void ComputeSHA3_256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SHAHelper.ComputeSHA3_256("hello").Length);
    }

    /// <summary>
    /// 验证SHA3-384的十六进制输出长度为96个字符（384位）
    /// </summary>
    [Fact]
    public void ComputeSHA3_384_HasNinetySixHexChars()
    {
        Assert.Equal(96, SHAHelper.ComputeSHA3_384("hello").Length);
    }

    /// <summary>
    /// 验证SHA3-512的十六进制输出长度为128个字符（512位）
    /// </summary>
    [Fact]
    public void ComputeSHA3_512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, SHAHelper.ComputeSHA3_512("hello").Length);
    }

    /// <summary>
    /// 验证SHA3-256与SHA-256的计算结果不同
    /// </summary>
    [Fact]
    public void SHA3_256_DiffersFromSHA256()
    {
        Assert.NotEqual(SHAHelper.ComputeSHA256("hello"), SHAHelper.ComputeSHA3_256("hello"));
    }

    /// <summary>
    /// 验证SHA-512与SHA-256的计算结果不同
    /// </summary>
    [Fact]
    public void SHA512_DiffersFromSHA256()
    {
        Assert.NotEqual(SHAHelper.ComputeSHA256("hello"), SHAHelper.ComputeSHA512("hello"));
    }

    /// <summary>
    /// 验证SHA-256计算结果具有确定性和输入敏感性
    /// </summary>
    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(SHAHelper.ComputeSHA256("a"), SHAHelper.ComputeSHA256("a"));
        Assert.NotEqual(SHAHelper.ComputeSHA256("a"), SHAHelper.ComputeSHA256("b"));
    }

    /// <summary>
    /// 验证文件SHA-256哈希与字符串哈希结果一致
    /// </summary>
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

    /// <summary>
    /// 验证对null字节数组进行SHA-256计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeSHA256_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SHAHelper.ComputeSHA256((byte[])null!));
    }

    /// <summary>
    /// 验证对null字符串进行SHA-256计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeSHA256_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SHAHelper.ComputeSHA256((string)null!));
    }
}