using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

/// <summary>
/// Hex（十六进制）编码算法单元测试
/// </summary>
public class HexHelperTests
{
    /// <summary>
    /// 验证Hex编码对已知向量的正确性
    /// </summary>
    [Theory]
    [InlineData("hello", "68656c6c6f")]
    [InlineData("Chet.Security", "436865742e5365637572697479")]
    public void EncodeString_KnownVectors(string input, string expected)
    {
        Assert.Equal(expected, HexHelper.EncodeString(input));
    }

    /// <summary>
    /// 验证Hex编码输出为小写格式
    /// </summary>
    [Fact]
    public void Encode_ProducesLowercaseHex()
    {
        var hex = HexHelper.EncodeString("ABCDEF");
        Assert.Equal(hex.ToLowerInvariant(), hex);
        Assert.Equal("414243444546", hex);
    }

    /// <summary>
    /// 验证字符串的Hex编解码往返一致性（含Unicode和emoji）
    /// </summary>
    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = HexHelper.EncodeString(text);
        Assert.Equal(text, HexHelper.DecodeToString(encoded));
    }

    /// <summary>
    /// 验证Hex解码对大小写不敏感
    /// </summary>
    [Fact]
    public void Decode_IsCaseInsensitive()
    {
        var lower = HexHelper.EncodeString("foobar");
        var upper = lower.ToUpperInvariant();
        Assert.Equal(HexHelper.Decode(lower), HexHelper.Decode(upper));
    }

    /// <summary>
    /// 验证对空字符串进行解码返回空字节数组
    /// </summary>
    [Fact]
    public void Decode_EmptyString_ReturnsEmptyArray()
    {
        Assert.Empty(HexHelper.Decode(string.Empty));
    }

    /// <summary>
    /// 验证对null字节数组进行编码时抛出异常
    /// </summary>
    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HexHelper.Encode(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行编码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => HexHelper.EncodeString(input!));
    }

    /// <summary>
    /// 验证对奇数长度的十六进制字符串进行解码时抛出异常
    /// </summary>
    [Fact]
    public void Decode_OddLength_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => HexHelper.Decode("abc"));
    }
}