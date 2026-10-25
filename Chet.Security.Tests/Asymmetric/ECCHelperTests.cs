using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

/// <summary>
/// ECC（椭圆曲线加密）单元测试
/// </summary>
public class ECCHelperTests
{
    /// <summary>
    /// 验证生成密钥对返回有效的PEM格式字符串
    /// </summary>
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    /// <summary>
    /// 验证签名和验签流程的正确性
    /// </summary>
    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = ECCHelper.Sign(data, priv);
        Assert.True(ECCHelper.Verify(data, signature, pub));
    }

    /// <summary>
    /// 验证对篡改数据进行验签时返回失败
    /// </summary>
    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = ECCHelper.GenerateKeyPair();
        var signature = ECCHelper.Sign("original-data", priv);
        Assert.False(ECCHelper.Verify("tampered-data", signature, pub));
    }

    /// <summary>
    /// 验证派生共享密钥返回32字节长度
    /// </summary>
    [Fact]
    public void DeriveSharedSecret_ReturnsThirtyTwoBytes()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var shared = ECCHelper.DeriveSharedSecret(privA, pubA);
        Assert.Equal(32, shared.Length);
    }

    /// <summary>
    /// 验证两对密钥之间派生的共享密钥具有对称性（Alice和Bob得到相同的共享密钥）
    /// </summary>
    [Fact]
    public void DeriveSharedSecret_IsSymmetricBetweenTwoKeyPairs()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var (pubB, privB) = ECCHelper.GenerateKeyPair();

        var aliceShared = ECCHelper.DeriveSharedSecret(privA, pubB);
        var bobShared = ECCHelper.DeriveSharedSecret(privB, pubA);

        Assert.Equal(aliceShared, bobShared);
    }

    /// <summary>
    /// 验证不同密钥对派生的共享密钥不同
    /// </summary>
    [Fact]
    public void DeriveSharedSecret_DiffersForDifferentKeyPairs()
    {
        var (pubA, privA) = ECCHelper.GenerateKeyPair();
        var (pubB, privB) = ECCHelper.GenerateKeyPair();
        var (pubC, _) = ECCHelper.GenerateKeyPair();

        var withB = ECCHelper.DeriveSharedSecret(privA, pubB);
        var withC = ECCHelper.DeriveSharedSecret(privA, pubC);
        Assert.NotEqual(withB, withC);
    }

    /// <summary>
    /// 验证对空或null数据进行签名时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Sign_NullOrEmptyData_Throws(string? data)
    {
        var (_, priv) = ECCHelper.GenerateKeyPair();
        Assert.ThrowsAny<ArgumentException>(() => ECCHelper.Sign(data!, priv));
    }
}