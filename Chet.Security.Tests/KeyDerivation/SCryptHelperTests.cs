using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

/// <summary>
/// SCrypt密钥派生算法单元测试（抗GPU/ASIC的密码哈希算法）
/// </summary>
public class SCryptHelperTests
{
    /// <summary>
    /// 验证SCrypt派生结果具有确定性
    /// </summary>
    [Fact]
    public void DeriveBytes_IsDeterministic()
    {
        // Use small N for speed while still exercising the SCrypt pipeline.
        var a = SCryptHelper.DeriveBytes("password", "fixed-salt", n: 1024, r: 8, p: 1);
        var b = SCryptHelper.DeriveBytes("password", "fixed-salt", n: 1024, r: 8, p: 1);
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证SCrypt默认派生长度为32字节
    /// </summary>
    [Fact]
    public void DeriveBytes_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, SCryptHelper.DeriveBytes("password", "salt", n: 1024).Length);
    }

    /// <summary>
    /// 验证SCrypt自定义派生长度被正确应用
    /// </summary>
    [Fact]
    public void DeriveBytes_CustomLengthRespected()
    {
        Assert.Equal(64, SCryptHelper.DeriveBytes("password", "salt", n: 1024, derivedLength: 64).Length);
    }

    /// <summary>
    /// 验证不同盐值产生不同的SCrypt派生结果
    /// </summary>
    [Fact]
    public void DeriveBytes_DifferentSaltProducesDifferentOutput()
    {
        var a = SCryptHelper.DeriveBytes("password", "salt-1", n: 1024);
        var b = SCryptHelper.DeriveBytes("password", "salt-2", n: 1024);
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证SCrypt的Base64和Hex输出具有确定性和格式一致性
    /// </summary>
    [Fact]
    public void DeriveBase64_AndDeriveHex_AreDeterministicAndConsistent()
    {
        var b64 = SCryptHelper.DeriveBase64("password", "salt", n: 1024);
        var hex = SCryptHelper.DeriveHex("password", "salt", n: 1024);
        Assert.Equal(b64, SCryptHelper.DeriveBase64("password", "salt", n: 1024));
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    /// <summary>
    /// 验证对空或null密码进行SCrypt派生时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveBytes_NullOrEmptyPassword_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => SCryptHelper.DeriveBytes(password!, "salt", n: 1024));
    }

    /// <summary>
    /// 验证使用非2的幂次方的N参数进行SCrypt派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveBytes_NonPowerOfTwoN_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => SCryptHelper.DeriveBytes("password", "salt", n: 100));
    }
}