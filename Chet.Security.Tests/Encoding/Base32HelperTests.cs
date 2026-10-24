using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

public class Base32HelperTests
{
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

    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base32Helper.Encode(Array.Empty<byte>()));
    }

    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = Base32Helper.EncodeString(text);
        Assert.Equal(text, Base32Helper.DecodeToString(encoded));
    }

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

    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base32Helper.Encode(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base32Helper.EncodeString(input!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base32Helper.Decode(input!));
    }

    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        Assert.Throws<FormatException>(() => Base32Helper.Decode("0!======"));
    }
}
