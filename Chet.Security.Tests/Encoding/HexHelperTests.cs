using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

public class HexHelperTests
{
    [Theory]
    [InlineData("hello", "68656c6c6f")]
    [InlineData("Chet.Security", "436865742e5365637572697479")]
    public void EncodeString_KnownVectors(string input, string expected)
    {
        Assert.Equal(expected, HexHelper.EncodeString(input));
    }

    [Fact]
    public void Encode_ProducesLowercaseHex()
    {
        var hex = HexHelper.EncodeString("ABCDEF");
        Assert.Equal(hex.ToLowerInvariant(), hex);
        Assert.Equal("414243444546", hex);
    }

    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        var encoded = HexHelper.EncodeString(text);
        Assert.Equal(text, HexHelper.DecodeToString(encoded));
    }

    [Fact]
    public void Decode_IsCaseInsensitive()
    {
        var lower = HexHelper.EncodeString("foobar");
        var upper = lower.ToUpperInvariant();
        Assert.Equal(HexHelper.Decode(lower), HexHelper.Decode(upper));
    }

    [Fact]
    public void Decode_EmptyString_ReturnsEmptyArray()
    {
        Assert.Empty(HexHelper.Decode(string.Empty));
    }

    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HexHelper.Encode(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => HexHelper.EncodeString(input!));
    }

    [Fact]
    public void Decode_OddLength_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => HexHelper.Decode("abc"));
    }
}
