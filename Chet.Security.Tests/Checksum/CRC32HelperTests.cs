using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

/// <summary>
/// CRC-32校验和算法单元测试
/// </summary>
public class CRC32HelperTests
{
    /// <summary>
    /// 验证对标准测试字符串"123456789"的CRC-32计算结果
    /// </summary>
    [Fact]
    public void ComputeHex_StandardCheckString123456789()
    {
        Assert.Equal("cbf43926", CRC32Helper.ComputeHex("123456789"));
    }

    /// <summary>
    /// 验证十六进制输出始终为8个字符
    /// </summary>
    [Fact]
    public void ComputeHex_AlwaysEightHexChars()
    {
        Assert.Equal(8, CRC32Helper.ComputeHex("anything").Length);
    }

    /// <summary>
    /// 验证十六进制输出为小写格式
    /// </summary>
    [Fact]
    public void ComputeHex_IsLowercase()
    {
        var hex = CRC32Helper.ComputeHex("data");
        Assert.Equal(hex.ToLowerInvariant(), hex);
    }

    /// <summary>
    /// 验证Compute方法返回正确的uint值
    /// </summary>
    [Fact]
    public void Compute_ReturnsUintValue()
    {
        Assert.Equal((uint)0xcbf43926, CRC32Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789")));
    }

    /// <summary>
    /// 验证ComputeBytes返回4字节的小端序结果
    /// </summary>
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

    /// <summary>
    /// 验证计算结果具有确定性和输入敏感性
    /// </summary>
    [Fact]
    public void Compute_IsDeterministicAndInputSensitive()
    {
        Assert.Equal(CRC32Helper.ComputeHex("a"), CRC32Helper.ComputeHex("a"));
        Assert.NotEqual(CRC32Helper.ComputeHex("a"), CRC32Helper.ComputeHex("b"));
    }

    /// <summary>
    /// 验证文件校验和与字符串校验和结果一致
    /// </summary>
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

    /// <summary>
    /// 验证对不存在的文件进行计算时抛出FileNotFoundException
    /// </summary>
    [Fact]
    public void ComputeFileHex_MissingFile_Throws()
    {
        Assert.Throws<FileNotFoundException>(() => CRC32Helper.ComputeFileHex(Path.GetTempFileName() + ".missing"));
    }

    /// <summary>
    /// 验证对null字节数组进行计算时抛出异常
    /// </summary>
    [Fact]
    public void Compute_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CRC32Helper.Compute(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行十六进制计算时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => CRC32Helper.ComputeHex(input!));
    }
}