using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

/// <summary>
/// SM3（国密哈希算法）单元测试
/// </summary>
public class SM3HelperTests
{
    /// <summary>
    /// 验证SM3的十六进制输出长度为64个字符（256位）
    /// </summary>
    [Fact]
    public void ComputeHash_HasSixtyFourHexChars()
    {
        Assert.Equal(64, SM3Helper.ComputeHash("abc").Length);
    }

    /// <summary>
    /// 验证SM3字节数组输出为32字节
    /// </summary>
    [Fact]
    public void ComputeHashBytes_ReturnsThirtyTwoBytes()
    {
        Assert.Equal(32, SM3Helper.ComputeHashBytes(System.Text.Encoding.UTF8.GetBytes("abc")).Length);
    }

    /// <summary>
    /// 验证SM3计算结果具有确定性
    /// </summary>
    [Fact]
    public void ComputeHash_IsDeterministic()
    {
        Assert.Equal(SM3Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abc"));
    }

    /// <summary>
    /// 验证SM3计算结果对输入敏感
    /// </summary>
    [Fact]
    public void ComputeHash_IsInputSensitive()
    {
        Assert.NotEqual(SM3Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abd"));
    }

    /// <summary>
    /// 验证SM3与MD5的计算结果不同
    /// </summary>
    [Fact]
    public void ComputeHash_DiffersFromMD5()
    {
        Assert.NotEqual(MD5Helper.ComputeHash("abc"), SM3Helper.ComputeHash("abc"));
    }

    /// <summary>
    /// 验证SM3的Base64输出与字节数组输出一致
    /// </summary>
    [Fact]
    public void ComputeHashBase64_MatchesBytes()
    {
        var hex = SM3Helper.ComputeHash("abc");
        var bytes = HexHelper.Decode(hex);
        Assert.Equal(Convert.ToBase64String(bytes), SM3Helper.ComputeHashBase64("abc"));
    }

    /// <summary>
    /// 验证SM3计算结果非空
    /// </summary>
    [Fact]
    public void ComputeHash_NonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(SM3Helper.ComputeHash("hello")));
    }

    /// <summary>
    /// 验证对null字节数组进行SM3计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeHash_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SM3Helper.ComputeHash((byte[])null!));
    }

    /// <summary>
    /// 验证对null字符串进行SM3计算时抛出异常
    /// </summary>
    [Fact]
    public void ComputeString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SM3Helper.ComputeHash((string)null!));
    }
}