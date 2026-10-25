using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

/// <summary>
/// DSA（数字签名算法）单元测试
/// </summary>
public class DSAHelperTests
{
    /// <summary>
    /// 验证生成的密钥对为PEM格式字符串
    /// </summary>
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    /// <summary>
    /// 验证使用无效密钥大小生成密钥对时抛出异常
    /// </summary>
    [Fact]
    public void GenerateKeyPair_InvalidKeySize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DSAHelper.GenerateKeyPair(2049));
    }

    /// <summary>
    /// 验证使用DSA签名和验证的往返一致性
    /// </summary>
    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = DSAHelper.Sign(data, priv);
        Assert.True(DSAHelper.Verify(data, signature, pub));
    }

    /// <summary>
    /// 验证对篡改数据进行签名验证时返回false
    /// </summary>
    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var signature = DSAHelper.Sign("original-data", priv);
        Assert.False(DSAHelper.Verify("tampered-data", signature, pub));
    }

    /// <summary>
    /// 验证不同次签名调用产生不同但均有效的签名（DSA包含随机数）
    /// </summary>
    [Fact]
    public void Sign_DifferentInvocationsProduceValidButPotentiallyDifferentSignatures()
    {
        var (pub, priv) = DSAHelper.GenerateKeyPair();
        var data = "some-data";
        var sig1 = DSAHelper.Sign(data, priv);
        var sig2 = DSAHelper.Sign(data, priv);
        // Both must verify.
        Assert.True(DSAHelper.Verify(data, sig1, pub));
        Assert.True(DSAHelper.Verify(data, sig2, pub));
    }

    /// <summary>
    /// 验证对空或null数据进行签名时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Sign_NullOrEmptyData_Throws(string? data)
    {
        var (_, priv) = DSAHelper.GenerateKeyPair();
        Assert.ThrowsAny<ArgumentException>(() => DSAHelper.Sign(data!, priv));
    }
}