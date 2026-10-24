using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

public class Base64HelperTests
{
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

    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base64Helper.Encode(Array.Empty<byte>()));
    }

    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base64Helper.EncodeString(text);
        Assert.Equal(text, Base64Helper.DecodeToString(encoded));
    }

    [Fact]
    public void RoundTrip_UrlSafe_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base64Helper.EncodeStringUrlSafe(text);
        Assert.Equal(text, Base64Helper.DecodeToString(encoded));
    }

    [Fact]
    public void EncodeUrlSafe_HasNoPaddingOrStandardSpecialChars()
    {
        var urlSafe = Base64Helper.EncodeStringUrlSafe("???");
        Assert.DoesNotContain("=", urlSafe);
        Assert.DoesNotContain("+", urlSafe);
        Assert.DoesNotContain("/", urlSafe);
    }

    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base64Helper.Encode(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base64Helper.EncodeString(input!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base64Helper.Decode(input!));
    }

    [Fact]
    public void Decode_InvalidLength_Throws()
    {
        // length % 4 == 1 is an invalid Base64 length.
        Assert.Throws<FormatException>(() => Base64Helper.Decode("x"));
    }
}
