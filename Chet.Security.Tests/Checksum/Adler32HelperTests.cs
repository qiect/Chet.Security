using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

/// <summary>
/// Adler-32校验和算法单元测试
/// </summary>
public class Adler32HelperTests
{
    /// <summary>
    /// 验证对Wikipedia已知向量的Adler-32计算结果
    /// </summary>
    [Fact]
    public void ComputeHex_KnownWikipediaVector()
    {
        Assert.Equal("11e60398", Adler32Helper.ComputeHex("Wikipedia"));
    }

    /// <summary>
    /// 验证十六进制输出始终为8个字符
    /// </summary>
    [Fact]
    public void ComputeHex_AlwaysEightHexChars()
    {
        Assert.Equal(8, Adler32Helper.ComputeHex("123456789").Length);
    }

    /// <summary>
    /// 验证十六进制输出为小写格式
    /// </summary>
    [Fact]
    public void ComputeHex_IsLowercase()
    {
        var hex = Adler32Helper.ComputeHex("Wikipedia");
        Assert.Equal(hex.ToLowerInvariant(), hex);
    }

    /// <summary>
    /// 验证Compute方法返回正确的uint值
    /// </summary>
    [Fact]
    public void Compute_ReturnsUintValue()
    {
        Assert.Equal((uint)0x11e60398, Adler32Helper.Compute(System.Text.Encoding.UTF8.GetBytes("Wikipedia")));
    }

    /// <summary>
    /// 验证ComputeBytes返回4字节的小端序结果
    /// </summary>
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

    /// <summary>
    /// 验证计算结果具有确定性和输入敏感性
    /// </summary>
    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(Adler32Helper.ComputeHex("abc"), Adler32Helper.ComputeHex("abc"));
        Assert.NotEqual(Adler32Helper.ComputeHex("a"), Adler32Helper.ComputeHex("b"));
    }

    /// <summary>
    /// 验证文件校验和与字符串校验和结果一致
    /// </summary>
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

    /// <summary>
    /// 验证对null字节数组进行计算时抛出异常
    /// </summary>
    [Fact]
    public void Compute_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Adler32Helper.Compute(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行十六进制计算时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => Adler32Helper.ComputeHex(input!));
    }
}