using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Random;

/// <summary>
/// 安全随机数生成器单元测试
/// </summary>
public class SecureRandomHelperTests
{
    /// <summary>
    /// 验证生成指定长度的随机字节数组
    /// </summary>
    [Fact]
    public void GenerateBytes_ReturnsRequestedLength()
    {
        Assert.Equal(32, SecureRandomHelper.GenerateBytes(32).Length);
    }

    /// <summary>
    /// 验证生成长度为0的随机字节数组返回空数组
    /// </summary>
    [Fact]
    public void GenerateBytes_ZeroLength_ReturnsEmptyArray()
    {
        Assert.Empty(SecureRandomHelper.GenerateBytes(0));
    }

    /// <summary>
    /// 验证使用负长度生成随机字节时抛出异常
    /// </summary>
    [Fact]
    public void GenerateBytes_NegativeLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomHelper.GenerateBytes(-1));
    }

    /// <summary>
    /// 验证两次生成的随机字节不同（随机性）
    /// </summary>
    [Fact]
    public void GenerateBytes_TwoCallsDiffer()
    {
        Assert.NotEqual(SecureRandomHelper.GenerateBytes(16), SecureRandomHelper.GenerateBytes(16));
    }

    /// <summary>
    /// 验证生成的随机整数在指定范围内
    /// </summary>
    [Fact]
    public void GenerateInt_WithRange_StaysWithinBounds()
    {
        for (var i = 0; i < 100; i++)
        {
            var v = SecureRandomHelper.GenerateInt(10, 20);
            Assert.True(v >= 10 && v < 20);
        }
    }

    /// <summary>
    /// 验证范围为1时始终返回最小值
    /// </summary>
    [Fact]
    public void GenerateInt_RangeOfOne_AlwaysReturnsMin()
    {
        for (var i = 0; i < 20; i++)
            Assert.Equal(5, SecureRandomHelper.GenerateInt(5, 6));
    }

    /// <summary>
    /// 验证使用无效范围（最大值小于最小值）生成随机整数时抛出异常
    /// </summary>
    [Fact]
    public void GenerateInt_InvalidRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomHelper.GenerateInt(10, 5));
    }

    /// <summary>
    /// 验证十六进制输出长度为字节数的两倍
    /// </summary>
    [Fact]
    public void GenerateHex_LengthIsDoubleByteLength()
    {
        Assert.Equal(32, SecureRandomHelper.GenerateHex(16).Length);
    }

    /// <summary>
    /// 验证Base64输出非空
    /// </summary>
    [Fact]
    public void GenerateBase64_NonEmpty()
    {
        Assert.False(string.IsNullOrEmpty(SecureRandomHelper.GenerateBase64(16)));
    }

    /// <summary>
    /// 验证生成密码的长度符合请求
    /// </summary>
    [Fact]
    public void GeneratePassword_LengthMatchesRequest()
    {
        Assert.Equal(20, SecureRandomHelper.GeneratePassword(20).Length);
    }

    /// <summary>
    /// 验证不含符号的密码仅包含字母和数字
    /// </summary>
    [Fact]
    public void GeneratePassword_WithoutSymbols_ContainsOnlyAlphanumerics()
    {
        var pw = SecureRandomHelper.GeneratePassword(40, includeSymbols: false);
        Assert.Equal(40, pw.Length);
        Assert.All(pw, c => Assert.True(char.IsLetterOrDigit(c)));
    }

    /// <summary>
    /// 验证生成的UUID可被解析为Guid
    /// </summary>
    [Fact]
    public void GenerateUuid_IsParseableAsGuid()
    {
        Assert.True(Guid.TryParse(SecureRandomHelper.GenerateUuid(), out _));
    }

    /// <summary>
    /// 验证生成的随机双精度浮点数在[0, 1)区间内
    /// </summary>
    [Fact]
    public void GenerateDouble_StaysWithinUnitHalfOpenInterval()
    {
        for (var i = 0; i < 100; i++)
        {
            var d = SecureRandomHelper.GenerateDouble();
            Assert.True(d >= 0.0 && d < 1.0);
        }
    }

    /// <summary>
    /// 验证Fill方法用非零字节填充缓冲区
    /// </summary>
    [Fact]
    public void Fill_PopulatesBufferWithNonZeroBytes()
    {
        var buffer = new byte[16];
        SecureRandomHelper.Fill(buffer);
        Assert.NotEqual(new byte[16], buffer);
    }

    /// <summary>
    /// 验证对null缓冲区调用Fill方法时抛出异常
    /// </summary>
    [Fact]
    public void Fill_NullBuffer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SecureRandomHelper.Fill(null!));
    }
}