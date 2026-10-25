using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

/// <summary>
/// Base64编码算法单元测试
/// </summary>
public class Base64HelperTests
{
    /// <summary>
    /// 验证Base64编码对RFC 4648已知向量的正确性
    /// </summary>
    [Theory]
    [InlineData("f", "Zg==")]
    [InlineData("fo", "Zm8=")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foobar", "Zm9vYmFy")]
    [InlineData("hello", "aGVsbG8=")]
    [InlineData("Chet.Security", "Q2hldC5TZWN1cml0eQ==")]
    public void EncodeString_KnownRfc4648Vectors(string input, string expected)
    {
        Assert.Equal(expected, Base64Helper.EncodeString(input));
    }

    /// <summary>
    /// 验证对空字节数组编码返回空字符串
    /// </summary>
    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base64Helper.Encode(Array.Empty<byte>()));
    }

    /// <summary>
    /// 验证标准Base64字符串的编解码往返一致性（含Unicode和emoji）
    /// </summary>
    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base64Helper.EncodeString(text);
        Assert.Equal(text, Base64Helper.DecodeToString(encoded));
    }

    /// <summary>
    /// 验证URL安全Base64字符串的编解码往返一致性
    /// </summary>
    [Fact]
    public void RoundTrip_UrlSafe_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base64Helper.EncodeStringUrlSafe(text);
        Assert.Equal(text, Base64Helper.DecodeToString(encoded));
    }

    /// <summary>
    /// 验证URL安全Base64编码不包含填充符(=)和标准特殊字符(+/)
    /// </summary>
    [Fact]
    public void EncodeUrlSafe_HasNoPaddingOrStandardSpecialChars()
    {
        var urlSafe = Base64Helper.EncodeStringUrlSafe("???");
        Assert.DoesNotContain("=", urlSafe);
        Assert.DoesNotContain("+", urlSafe);
        Assert.DoesNotContain("/", urlSafe);
    }

    /// <summary>
    /// 验证对null字节数组进行编码时抛出异常
    /// </summary>
    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base64Helper.Encode(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行编码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base64Helper.EncodeString(input!));
    }

    /// <summary>
    /// 验证对空或null字符串进行解码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base64Helper.Decode(input!));
    }

    /// <summary>
    /// 验证对无效长度的Base64字符串进行解码时抛出FormatException
    /// </summary>
    [Fact]
    public void Decode_InvalidLength_Throws()
    {
        // length % 4 == 1 is an invalid Base64 length.
        Assert.Throws<FormatException>(() => Base64Helper.Decode("x"));
    }
}