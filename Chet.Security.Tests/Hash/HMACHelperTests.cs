using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

/// <summary>
/// HMAC（基于哈希的消息认证码）算法单元测试
/// </summary>
public class HMACHelperTests
{
    /// <summary>
    /// 验证HMAC-SHA256的十六进制输出长度为64个字符（256位）
    /// </summary>
    [Fact]
    public void HmacSHA256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, HMACHelper.ComputeHmacSHA256("Hi There", "secret-key").Length);
    }

    /// <summary>
    /// 验证HMAC-MD5的十六进制输出长度为32个字符（128位）
    /// </summary>
    [Fact]
    public void HmacMD5_HasThirtyTwoHexChars()
    {
        Assert.Equal(32, HMACHelper.ComputeHmacMD5("Hi There", "secret-key").Length);
    }

    /// <summary>
    /// 验证HMAC-SHA1的十六进制输出长度为40个字符（160位）
    /// </summary>
    [Fact]
    public void HmacSHA1_HasFortyHexChars()
    {
        Assert.Equal(40, HMACHelper.ComputeHmacSHA1("Hi There", "secret-key").Length);
    }

    /// <summary>
    /// 验证HMAC-SHA384的十六进制输出长度为96个字符（384位）
    /// </summary>
    [Fact]
    public void HmacSHA384_HasNinetySixHexChars()
    {
        Assert.Equal(96, HMACHelper.ComputeHmacSHA384("Hi There", "secret-key").Length);
    }

    /// <summary>
    /// 验证HMAC-SHA512的十六进制输出长度为128个字符（512位）
    /// </summary>
    [Fact]
    public void HmacSHA512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, HMACHelper.ComputeHmacSHA512("Hi There", "secret-key").Length);
    }

    /// <summary>
    /// 验证HMAC-SM3的十六进制输出长度为64个字符且非空
    /// </summary>
    [Fact]
    public void HmacSM3_HasSixtyFourHexCharsAndNonEmpty()
    {
        var mac = HMACHelper.ComputeHmacSM3("Hi There", "secret-key");
        Assert.Equal(64, mac.Length);
        Assert.False(string.IsNullOrWhiteSpace(mac));
    }

    /// <summary>
    /// 验证HMAC-SHA256计算结果具有确定性
    /// </summary>
    [Fact]
    public void HmacSHA256_IsDeterministic()
    {
        Assert.Equal(
            HMACHelper.ComputeHmacSHA256("message", "key"),
            HMACHelper.ComputeHmacSHA256("message", "key"));
    }

    /// <summary>
    /// 验证HMAC-SHA256计算结果对密钥敏感
    /// </summary>
    [Fact]
    public void HmacSHA256_IsKeySensitive()
    {
        Assert.NotEqual(
            HMACHelper.ComputeHmacSHA256("message", "key1"),
            HMACHelper.ComputeHmacSHA256("message", "key2"));
    }

    /// <summary>
    /// 验证HMAC-SHA256计算结果对数据敏感
    /// </summary>
    [Fact]
    public void HmacSHA256_IsDataSensitive()
    {
        Assert.NotEqual(
            HMACHelper.ComputeHmacSHA256("message1", "key"),
            HMACHelper.ComputeHmacSHA256("message2", "key"));
    }

    /// <summary>
    /// 验证HMAC-SHA256字节数组输出长度为32字节
    /// </summary>
    [Fact]
    public void HmacSHA256Bytes_LengthIsThirtyTwo()
    {
        Assert.Equal(32,
            HMACHelper.ComputeHmacSHA256Bytes(System.Text.Encoding.UTF8.GetBytes("data"),
                System.Text.Encoding.UTF8.GetBytes("key")).Length);
    }

    /// <summary>
    /// 验证对null数据进行HMAC-SHA256计算时抛出异常
    /// </summary>
    [Fact]
    public void HmacSHA256_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HMACHelper.ComputeHmacSHA256((byte[])null!, new byte[] { 1 }));
    }

    /// <summary>
    /// 验证对null密钥进行HMAC-SHA256计算时抛出异常
    /// </summary>
    [Fact]
    public void HmacSHA256_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HMACHelper.ComputeHmacSHA256(new byte[] { 1 }, (byte[])null!));
    }

    /// <summary>
    /// 验证对null文本进行HMAC-SHA256计算时抛出异常
    /// </summary>
    [Fact]
    public void HmacSHA256_NullText_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => HMACHelper.ComputeHmacSHA256((string)null!, "key"));
    }
}