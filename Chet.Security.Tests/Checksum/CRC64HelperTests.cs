using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Checksum;

/// <summary>
/// CRC-64校验和算法单元测试
/// </summary>
public class CRC64HelperTests
{
    /// <summary>
    /// 验证十六进制输出为非空的小写格式
    /// </summary>
    [Fact]
    public void ComputeHex_ReturnsNonEmptyLowercaseHex()
    {
        var hex = CRC64Helper.ComputeHex("123456789");
        Assert.False(string.IsNullOrEmpty(hex));
        Assert.All(hex, c => Assert.True((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }

    /// <summary>
    /// 验证对非空输入Compute返回非零ulong值
    /// </summary>
    [Fact]
    public void Compute_ReturnsNonZeroUlongForNonEmptyInput()
    {
        Assert.NotEqual((ulong)0, CRC64Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789")));
    }

    /// <summary>
    /// 验证ComputeBytes返回8字节的小端序结果
    /// </summary>
    [Fact]
    public void ComputeBytes_ReturnsEightBytesLittleEndian()
    {
        var bytes = CRC64Helper.ComputeBytes(System.Text.Encoding.UTF8.GetBytes("123456789"));
        Assert.Equal(8, bytes.Length);
        Assert.Equal(bytes, BitConverter.GetBytes(CRC64Helper.Compute(System.Text.Encoding.UTF8.GetBytes("123456789"))));
    }

    /// <summary>
    /// 验证计算结果具有确定性
    /// </summary>
    [Fact]
    public void Compute_IsDeterministic()
    {
        Assert.Equal(CRC64Helper.ComputeHex("abc"), CRC64Helper.ComputeHex("abc"));
    }

    /// <summary>
    /// 验证计算结果对输入敏感（不同输入产生不同结果）
    /// </summary>
    [Fact]
    public void Compute_IsInputSensitive()
    {
        Assert.NotEqual(CRC64Helper.ComputeHex("a"), CRC64Helper.ComputeHex("b"));
    }

    /// <summary>
    /// 验证CRC-64与CRC-32的计算结果不同
    /// </summary>
    [Fact]
    public void Compute_DiffersFromCRC32()
    {
        Assert.NotEqual(CRC32Helper.ComputeHex("123456789"), CRC64Helper.ComputeHex("123456789"));
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
            Assert.Equal(CRC64Helper.ComputeHex("123456789"), CRC64Helper.ComputeFileHex(path));
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
        Assert.Throws<ArgumentNullException>(() => CRC64Helper.Compute(null!));
    }

    /// <summary>
    /// 验证对空或null字符串进行十六进制计算时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeHex_NullOrEmpty_Throws(string? input)
    {
        Assert.ThrowsAny<ArgumentException>(() => CRC64Helper.ComputeHex(input!));
    }
}