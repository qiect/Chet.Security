using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

public class CRC32HelperTests
{
    [Fact]
    public void ComputeHex_StandardCheckString123456789()
    {
        Assert.Equal("cbf43926", CRC32Helper.ComputeHex("123456789"));
    }

    [Fact]
    public void ComputeHex_AlwaysEightHexChars()
    {
        Assert.Equal(8, CRC32Helper.ComputeHex("anything").Length);
    }

    [Fact]
    public void ComputeHex_IsLowercase()
    {
        var hex = CRC32Helper.ComputeHex("data");
        Assert.Equal(hex.ToLowerInvariant(), hex);
    }

    [Fact]
    public void Compute_ReturnsUintValue()
    {
        Assert.Equal((uint)0xcbf43926, CRC32Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789")));
    }

    [Fact]
    public void ComputeBytes_ReturnsFourBytesLittleEndian()
    {
        var bytes = CRC32Helper.ComputeBytes(System.Text.Encoding.UTF8.GetBytes("123456789"));
        Assert.Equal(4, bytes.Length);
        Assert.Equal(0x26, bytes[0]);
        Assert.Equal(0x39, bytes[1]);
        Assert.Equal(0xf4, bytes[2]);
        Assert.Equal(0xcb, bytes[3]);
    }

    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(CRC32Helper.ComputeHex("a"), CRC32Helper.ComputeHex("a"));
        Assert.NotEqual(CRC32Helper.ComputeHex("a"), CRC32Helper.ComputeHex("b"));
    }

    [Fact]
    public void ComputeFileHex_MatchesStringHash()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "123456789");
        try
        {
            Assert.Equal("cbf43926", CRC32Helper.ComputeFileHex(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ComputeFileHex_MissingFile_Throws()
    {
        Assert.Throws<FileNotFoundException>(() => CRC32Helper.ComputeFileHex(Path.GetTempFileName() + ".missing"));
    }

    [Fact]
    public void Compute_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CRC32Helper.Compute(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => CRC32Helper.ComputeHex(input!));
    }
}
