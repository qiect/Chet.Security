using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

/// <summary>
/// PBKDF2密钥派生算法单元测试
/// </summary>
public class PBKDF2HelperTests
{
    /// <summary>
    /// 验证PBKDF2派生结果具有确定性
    /// </summary>
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        var a = PBKDF2Helper.DeriveBytes("password", "fixed-salt", iterations: 1000);
        var b = PBKDF2Helper.DeriveBytes("password", "fixed-salt", iterations: 1000);
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证PBKDF2默认派生长度为32字节
    /// </summary>
    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, PBKDF2Helper.DeriveBytes("password", "salt").Length);
    }

    /// <summary>
    /// 验证PBKDF2自定义派生长度被正确应用
    /// </summary>
    [Fact]
    public void DeriveBytes_CustomLengthRespected()
    {
        Assert.Equal(64, PBKDF2Helper.DeriveBytes("password", "salt", 100, 64).Length);
    }

    /// <summary>
    /// 验证不同盐值产生不同的PBKDF2派生结果
    /// </summary>
    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = PBKDF2Helper.DeriveBytes("password", "salt-1");
        var b = PBKDF2Helper.DeriveBytes("password", "salt-2");
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证PBKDF2的Base64和Hex输出具有确定性和格式一致性
    /// </summary>
    [Fact]
    public void DeriveBase64_AndDeriveHex_AreDeterministicAndConsistent()
    {
        var b64 = PBKDF2Helper.DeriveBase64("password", "salt", 1000);
        var hex = PBKDF2Helper.DeriveHex("password", "salt", 1000);
        Assert.Equal(b64, PBKDF2Helper.DeriveBase64("password", "salt", 1000));
        Assert.Equal(hex, PBKDF2Helper.DeriveHex("password", "salt", 1000));
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    /// <summary>
    /// 验证生成盐值的默认长度为16字节
    /// </summary>
    [Fact]
    public void GenerateSalt_DefaultLengthIsSixteen()
    {
        Assert.Equal(16, PBKDF2Helper.GenerateSalt().Length);
    }

    /// <summary>
    /// 验证生成盐值的自定义长度被正确应用
    /// </summary>
    [Fact]
    public void GenerateSalt_CustomLengthRespected()
    {
        Assert.Equal(32, PBKDF2Helper.GenerateSalt(32).Length);
    }

    /// <summary>
    /// 验证不同次生成的盐值不同（随机性）
    /// </summary>
    [Fact]
    public void GenerateSalt_DifferentCallsDiffer()
    {
        Assert.NotEqual(PBKDF2Helper.GenerateSalt(), PBKDF2Helper.GenerateSalt());
    }

    /// <summary>
    /// 验证对空或null密码进行PBKDF2派生时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => PBKDF2Helper.DeriveBytes(password!, "salt"));
    }

    /// <summary>
    /// 验证对null盐值进行PBKDF2派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveBytes_NullSalt_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => PBKDF2Helper.DeriveBytes("password", (byte[])null!));
    }

    /// <summary>
    /// 验证使用非正迭代次数进行PBKDF2派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveBytes_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PBKDF2Helper.DeriveBytes("password", "salt", 0));
    }
}