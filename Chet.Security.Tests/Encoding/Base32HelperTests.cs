using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

/// <summary>
/// Base32编码算法单元测试
/// </summary>
public class Base32HelperTests
{
    /// <summary>
    /// 验证Base32编码对RFC 4648已知向量的正确性
    /// </summary>
    [Theory]
    [InlineData("f", "MY======")]
    [InlineData("fo", "MZXQ====")]
    [InlineData("foo", "MZXW6===")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI======")]
    public void EncodeString_KnownRfc4648Vectors(string input, string expected)
    {
        Assert.Equal(expected, Base32Helper.EncodeString(input));
    }

    /// <summary>
    /// 验证对空字节数组编码返回空字符串
    /// </summary>
    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base32Helper.Encode(Array.Empty<byte>()));
    }

    /// <summary>
    /// 验证字符串的Base32编解码往返一致性（含Unicode和emoji）
    /// </summary>
    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base32Helper.EncodeString(text);
        Assert.Equal(text, Base32Helper.DecodeToString(encoded));
    }

    /// <summary>
    /// 验证Base32解码对大小写不敏感
    /// </summary>
    [Fact]
    public void Decode_IsCaseInsensitive()
    {
        var upper = Base32Helper.EncodeString("foobar");
        var lower = upper.ToLowerInvariant();
        var fromUpper = Base32Helper.DecodeToString(upper);
        var fromLower = Base32Helper.DecodeToString(lower);
        Assert.Equal(fromUpper, fromLower);
        Assert.Equal("foobar", fromLower);
    }

    /// <summary>
    /// 验证对null字节数组进行编码时抛出异常
    /// </summary>
    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base32Helper.Encode(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行编码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base32Helper.EncodeString(input!));
    }

    /// <summary>
    /// 验证对空或null字符串进行解码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base32Helper.Decode(input!));
    }

    /// <summary>
    /// 验证对包含无效字符的字符串进行解码时抛出FormatException
    /// </summary>
    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        Assert.Throws<FormatException>(() => Base32Helper.Decode("0!======"));
    }
}