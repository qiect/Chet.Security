using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

/// <summary>
/// Blake2哈希算法单元测试（包含Blake2b和Blake2s两种变体）
/// </summary>
public class Blake2HelperTests
{
    /// <summary>
    /// 验证Blake2b的十六进制输出长度为128个字符（512位）
    /// </summary>
    [Fact]
    public void Blake2b_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, Blake2Helper.ComputeBlake2b("hello").Length);
    }

    /// <summary>
    /// 验证Blake2s的十六进制输出长度为64个字符（256位）
    /// </summary>
    [Fact]
    public void Blake2s_HasSixtyFourHexChars()
    {
        Assert.Equal(64, Blake2Helper.ComputeBlake2s("hello").Length);
    }

    /// <summary>
    /// 验证Blake2b字节数组输出为64字节
    /// </summary>
    [Fact]
    public void Blake2bBytes_ReturnsSixtyFourBytes()
    {
        Assert.Equal(64, Blake2Helper.ComputeBlake2bBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    /// <summary>
    /// 验证Blake2s字节数组输出为32字节
    /// </summary>
    [Fact]
    public void Blake2sBytes_ReturnsThirtyTwoBytes()
    {
        Assert.Equal(32, Blake2Helper.ComputeBlake2sBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    /// <summary>
    /// 验证Blake2b计算结果具有确定性
    /// </summary>
    [Fact]
    public void Blake2b_IsDeterministic()
    {
        Assert.Equal(Blake2Helper.ComputeBlake2b("a"), Blake2Helper.ComputeBlake2b("a"));
    }

    /// <summary>
    /// 验证Blake2b计算结果对输入敏感
    /// </summary>
    [Fact]
    public void Blake2b_IsInputSensitive()
    {
        Assert.NotEqual(Blake2Helper.ComputeBlake2b("a"), Blake2Helper.ComputeBlake2b("b"));
    }

    /// <summary>
    /// 验证Blake2s计算结果对输入敏感
    /// </summary>
    [Fact]
    public void Blake2s_IsInputSensitive()
    {
        Assert.NotEqual(Blake2Helper.ComputeBlake2s("a"), Blake2Helper.ComputeBlake2s("b"));
    }

    /// <summary>
    /// 验证带密钥的Blake2b计算结果与无密钥的不同
    /// </summary>
    [Fact]
    public void Blake2b_KeyedDiffersFromUnkeyed()
    {
        var unkeyed = Blake2Helper.ComputeBlake2b("data");
        var keyed = Blake2Helper.ComputeBlake2b(System.Text.Encoding.UTF8.GetBytes("data"),
            System.Text.Encoding.UTF8.GetBytes("key"));
        Assert.NotEqual(unkeyed, keyed);
        Assert.Equal(128, keyed.Length);
    }

    /// <summary>
    /// 验证使用空密钥的Blake2b计算结果与无密钥一致
    /// </summary>
    [Fact]
    public void Blake2b_KeyedWithEmptyKeyEqualsUnkeyed()
    {
        var unkeyed = Blake2Helper.ComputeBlake2b("data");
        var emptyKey = Blake2Helper.ComputeBlake2b(System.Text.Encoding.UTF8.GetBytes("data"), Array.Empty<byte>());
        Assert.Equal(unkeyed, emptyKey);
    }

    /// <summary>
    /// 验证对null字节数组进行Blake2b计算时抛出异常
    /// </summary>
    [Fact]
    public void Blake2b_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Blake2Helper.ComputeBlake2b((byte[])null!));
    }

    /// <summary>
    /// 验证对null字符串进行Blake2b计算时抛出异常
    /// </summary>
    [Fact]
    public void Blake2bString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => Blake2Helper.ComputeBlake2b((string)null!));
    }
}