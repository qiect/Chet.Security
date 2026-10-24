using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Encoding;

public class Base58HelperTests
{
    [Fact]
    public void Encode_SingleLeadingZeroByte_ReturnsSingleOne()
    {
        Assert.Equal("1", Base58Helper.Encode(new byte[] { 0x00 }));
    }

    [Fact]
    public void Encode_TwoLeadingZeroBytes_ReturnsTwoOnes()
    {
        Assert.Equal("11", Base58Helper.Encode(new byte[] { 0x00, 0x00 }));
    }

    [Fact]
    public void Encode_SingleByteSixtyOne_ReturnsTwoG()
    {
        // 0x61 = 97 = 1*58 + 39 => alphabet[1]='2', alphabet[39]='g' => "2g"
        Assert.Equal("2g", Base58Helper.Encode(new byte[] { 0x61 }));
    }

    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, Base58Helper.Encode(Array.Empty<byte>()));
    }

    [Fact]
    public void RoundTrip_String_RecoversOriginal()
    {
        var text = "hello";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    [Fact]
    public void RoundTrip_HelloWorld_RecoversOriginal()
    {
        var text = "Hello World!";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    [Fact]
    public void RoundTrip_BinaryWithLeadingZeros_RecoversOriginal()
    {
        var bytes = new byte[] { 0x00, 0x00, 0x01, 0x02, 0xFF };
        var encoded = Base58Helper.Encode(bytes);
        Assert.Equal(bytes, Base58Helper.Decode(encoded));
    }

    [Fact]
    public void RoundTrip_Unicode_RecoversOriginal()
    {
        var text = "测试 Test 123 🔒";
        Assert.Equal(text, Base58Helper.DecodeToString(Base58Helper.EncodeString(text)));
    }

    [Fact]
    public void Encode_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Base58Helper.Encode(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EncodeString_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base58Helper.EncodeString(input!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decode_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Base58Helper.Decode(input!));
    }

    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        Assert.Throws<FormatException>(() => Base58Helper.Decode("0OIl"));
    }
}
