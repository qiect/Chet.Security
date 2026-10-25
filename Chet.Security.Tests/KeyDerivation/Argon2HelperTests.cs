using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

/// <summary>
/// Argon2密钥派生算法单元测试（抗GPU/ASIC的密码哈希算法）
/// </summary>
public class Argon2HelperTests
{
    /// <summary>
    /// 验证Argon2派生结果具有确定性
    /// </summary>
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        // Use light parameters (1MB memory, 1 iteration) to keep unit tests fast.
        var a = Argon2Helper.DeriveBytes("password", "fixed-salt", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password", "fixed-salt", iterations: 1, memoryKb: 1024);
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证Argon2默认派生长度为32字节
    /// </summary>
    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, Argon2Helper.DeriveBytes("password", "salt", iterations: 1, memoryKb: 1024).Length);
    }

    /// <summary>
    /// 验证Argon2十六进制输出长度为64个字符
    /// </summary>
    [Fact]
    public void DeriveHex_HasSixtyFourChars()
    {
        Assert.Equal(64, Argon2Helper.DeriveHex("password", "salt", iterations: 1, memoryKb: 1024).Length);
    }

    /// <summary>
    /// 验证不同盐值产生不同的Argon2派生结果
    /// </summary>
    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = Argon2Helper.DeriveBytes("password", "salt-1", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password", "salt-2", iterations: 1, memoryKb: 1024);
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证不同密码产生不同的Argon2派生结果
    /// </summary>
    [Fact]
    public void DeriveBytes_DifferentPasswordProducesDifferentOutput()
    {
        var a = Argon2Helper.DeriveBytes("password-1", "salt", iterations: 1, memoryKb: 1024);
        var b = Argon2Helper.DeriveBytes("password-2", "salt", iterations: 1, memoryKb: 1024);
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证Argon2的Base64和Hex输出格式一致性
    /// </summary>
    [Fact]
    public void DeriveBase64_AndDeriveHex_AreConsistent()
    {
        var b64 = Argon2Helper.DeriveBase64("password", "salt", iterations: 1, memoryKb: 1024);
        var hex = Argon2Helper.DeriveHex("password", "salt", iterations: 1, memoryKb: 1024);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    /// <summary>
    /// 验证对空或null密码进行Argon2派生时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            Argon2Helper.DeriveBytes(password!, "salt", iterations: 1, memoryKb: 1024));
    }

    /// <summary>
    /// 验证使用非正迭代次数进行Argon2派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveBytes_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Helper.DeriveBytes("password", "salt", iterations: 0, memoryKb: 1024));
    }
}