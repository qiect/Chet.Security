using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

public class Adler32HelperTests
{
    [Fact]
    public void ComputeHex_KnownWikipediaVector()
    {
        Assert.Equal("11e60398", Adler32Helper.ComputeHex("Wikipedia"));
    }

    [Fact]
    public void ComputeHex_AlwaysEightHexChars()
    {
        Assert.Equal(8, Adler32Helper.ComputeHex("123456789").Length);
    }

    [Fact]
    public void ComputeHex_IsLowercase()
    {
        var hex = Adler32Helper.ComputeHex("Wikipedia");
        Assert.Equal(hex.ToLowerInvariant(), hex);
    }

    [Fact]
    public void Compute_ReturnsUintValue()
    {
        Assert.Equal((uint)0x11e60398, Adler32Helper.Compute(System.Text.Encoding.UTF8.GetBytes("Wikipedia")));
    }

    [Fact]
    public void ComputeBytes_ReturnsFourBytesLittleEndian()
    {
        var bytes = Adler32Helper.ComputeBytes(System.Text.Encoding.UTF8.GetBytes("Wikipedia"));
        Assert.Equal(4, bytes.Length);
        Assert.Equal(0x98, bytes[0]);
        Assert.Equal(0x03, bytes[1]);
        Assert.Equal(0xe6, bytes[2]);
        Assert.Equal(0x11, bytes[3]);
    }

    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(Adler32Helper.ComputeHex("abc"), Adler32Helper.ComputeHex("abc"));
        Assert.NotEqual(Adler32Helper.ComputeHex("a"), Adler32Helper.ComputeHex("b"));
    }

    [Fact]
    public void ComputeFileHex_MatchesStringHash()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "Wikipedia");
        try
        {
            Assert.Equal("11e60398", Adler32Helper.ComputeFileHex(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Compute_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Adler32Helper.Compute(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Adler32Helper.ComputeHex(input!));
    }
}
