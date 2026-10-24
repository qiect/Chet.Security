using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

public class CRC64HelperTests
{
    [Fact]
    public void ComputeHex_ReturnsNonEmptyLowercaseHex()
    {
        var hex = CRC64Helper.ComputeHex("123456789");
        Assert.False(string.IsNullOrEmpty(hex));
        Assert.All(hex, c => Assert.True((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }

    [Fact]
    public void Compute_ReturnsNonZeroUlongForNonEmptyInput()
    {
        Assert.NotEqual((ulong)0, CRC64Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789")));
    }

    [Fact]
    public void ComputeBytes_ReturnsEightBytesLittleEndian()
    {
        var bytes = CRC64Helper.ComputeBytes(System.Text.Encoding.UTF8.GetBytes("123456789"));
        Assert.Equal(8, bytes.Length);
        Assert.Equal(bytes, BitConverter.GetBytes(CRC64Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789"))));
    }

    [Fact]
    public void Compute_IsDeterministic()
    {
        Assert.Equal(CRC64Helper.ComputeHex("abc"), CRC64Helper.ComputeHex("abc"));
    }

    [Fact]
    public void Compute_IsInputSensitive()
    {
        Assert.NotEqual(CRC64Helper.ComputeHex("a"), CRC64Helper.ComputeHex("b"));
    }

    [Fact]
    public void Compute_DiffersFromCRC32()
    {
        Assert.NotEqual(CRC32Helper.ComputeHex("123456789"), CRC64Helper.ComputeHex("123456789"));
    }

    [Fact]
    public void ComputeFileHex_MatchesStringHash()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "123456789");
        try
        {
            Assert.Equal(CRC64Helper.ComputeHex("123456789"), CRC64Helper.ComputeFileHex(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Compute_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CRC64Helper.Compute(null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => CRC64Helper.ComputeHex(input!));
    }
}
