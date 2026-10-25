using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

/// <summary>
/// Base58编码算法单元测试（用于比特币等场景）
/// </summary>
public class Base58HelperTests
{
    /// <summary>
    /// 验证单个前导零字节编码为"1"（Base58中0x00映射为'1'）
    /// </summary>
    [Fact]
    public void Encode_SingleLeadingZeroByte_ReturnsSingleOne()
    {
        Assert.Equal("1", Base58Helper.Encode(new byte[] { 0x00 }));
    }

    /// <summary>
    /// 验证两个前导零字节编码为"11"
    /// </summary>
    [Fact]
    public void Encode_TwoLeadingZeroBytes_ReturnsTwoOnes()
    {
        Assert.Equal("11", Base58Helper.Encode(new byte[] { 0x00, 0x00 }));
    }

    /// <summary>
    /// 验证单字节0x61的Base58编码结果为"2g"
    /// </summary>
    [Fact]
    public void Encode_SingleByteSixtyOne_ReturnsTwoG()
    {
        // 0x61 = 97 = 1*58 + 39 => alphabet[1]='2', alphabet[39]='g' => "2g"
        Assert.Equal("2g", Base58Helper.Encode(new byte[] { 0x61 }));
    }

    /// <summary>
    /// 验证对空字节数组编码返回空字符串
    /// </summary>
    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base58Helper.Encode(Array.Empty<byte>()));
    }

    /// <summary>
    /// 验证字符串的Base58编解码往返一致性
    /// </summary>
    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "hello";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    /// <summary>
    /// 验证"Hello World!"的Base58编解码往返一致性
    /// </summary>
    [Fact]
    public void RoundTrip_HelloWorld_RecoversOriginal()
    {
        var text = "Hello World!";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    /// <summary>
    /// 验证含前导零字节的二进制数据的Base58编解码往返一致性
    /// </summary>
    [Fact]
    public void RoundTrip_BinaryWithLeadingZeros_RecoversOriginal()
    {
        var bytes = new byte[] { 0x00, 0x00, 0x01, 0x02, 0xFF };
        var encoded = Base58Helper.Encode(bytes);
        Assert.Equal(bytes, Base58Helper.Decode(encoded));
    }

    /// <summary>
    /// 验证Unicode字符（含emoji）的Base58编解码往返一致性
    /// </summary>
    [Fact]
    public void RoundTrip_Unicode_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    /// <summary>
    /// 验证对null字节数组进行编码时抛出异常
    /// </summary>
    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base58Helper.Encode(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行编码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base58Helper.EncodeString(input!));
    }

    /// <summary>
    /// 验证对空或null字符串进行解码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base58Helper.Decode(input!));
    }

    /// <summary>
    /// 验证对包含无效字符的字符串进行解码时抛出FormatException
    /// </summary>
    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        Assert.Throws<FormatException>(() => Base58Helper.Decode("0OIl"));
    }
}