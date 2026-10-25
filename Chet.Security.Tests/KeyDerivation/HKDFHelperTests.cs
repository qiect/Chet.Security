using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

/// <summary>
/// HKDF（基于HMAC的密钥派生函数）单元测试
/// </summary>
public class HKDFHelperTests
{
    /// <summary>
    /// 验证HKDF派生结果具有确定性
    /// </summary>
    [Fact]
    public void DeriveKey_IsDeterministic()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt", "info");
        var b = HKDFHelper.DeriveKey("ikm", "salt", "info");
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证HKDF默认派生长度为32字节
    /// </summary>
    [Fact]
    public void DeriveKey_DefaultLengthIsThirtyTwo()
    {
        Assert.Equal(32, HKDFHelper.DeriveKey("ikm", "salt", "info").Length);
    }

    /// <summary>
    /// 验证HKDF自定义派生长度被正确应用
    /// </summary>
    [Fact]
    public void DeriveKey_CustomLengthRespected()
    {
        Assert.Equal(64, HKDFHelper.DeriveKey("ikm", "salt", "info", 64).Length);
    }

    /// <summary>
    /// 验证不同盐值产生不同的HKDF派生结果
    /// </summary>
    [Fact]
    public void DeriveKey_DifferentSaltProducesDifferentOutput()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt-1", "info");
        var b = HKDFHelper.DeriveKey("ikm", "salt-2", "info");
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证不同info参数产生不同的HKDF派生结果
    /// </summary>
    [Fact]
    public void DeriveKey_DifferentInfoProducesDifferentOutput()
    {
        var a = HKDFHelper.DeriveKey("ikm", "salt", "info-1");
        var b = HKDFHelper.DeriveKey("ikm", "salt", "info-2");
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// 验证HKDF的Base64和Hex输出格式一致性
    /// </summary>
    [Fact]
    public void DeriveKeyBase64_AndDeriveKeyHex_AreConsistent()
    {
        var b64 = HKDFHelper.DeriveKeyBase64("ikm", "salt", "info");
        var hex = HKDFHelper.DeriveKeyHex("ikm", "salt", "info");
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.FromBase64String(b64), HexHelper.Decode(hex));
    }

    /// <summary>
    /// 验证对null输入密钥材料进行HKDF派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveKey_NullIkm_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HKDFHelper.DeriveKey((byte[])null!, Array.Empty<byte>(), Array.Empty<byte>()));
    }

    /// <summary>
    /// 验证对空或null字符串输入密钥材料进行HKDF派生时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void DeriveKeyString_NullOrEmptyIkm_Throws(string? ikm)
    {
        Assert.ThrowsAny<ArgumentException>(() => HKDFHelper.DeriveKey(ikm!, "salt", "info"));
    }

    /// <summary>
    /// 验证使用非正派生长度进行HKDF派生时抛出异常
    /// </summary>
    [Fact]
    public void DeriveKey_NonPositiveLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HKDFHelper.DeriveKey("ikm", "salt", "info", 0));
    }
}