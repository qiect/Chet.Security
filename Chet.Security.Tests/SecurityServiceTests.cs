using Chet.Security;
using Xunit;

namespace Chet.Security.Tests;

/// <summary>
/// SecurityService统一服务门面单元测试
/// </summary>
public class SecurityServiceTests
{
    /// <summary>
    /// 验证构造函数正确设置算法和密钥属性
    /// </summary>
    [Fact]
    public void Constructor_SetsAlgorithmAndKeys()
    {
        var svc = new SecurityService(CryptoAlgorithm.AES, "key", "priv", "iv");
        Assert.Equal(CryptoAlgorithm.AES, svc.Algorithm);
        Assert.Equal("key", svc.Key);
        Assert.Equal("priv", svc.Key2);
        Assert.Equal("iv", svc.Iv);
    }

    /// <summary>
    /// 验证AES算法通过SecurityService的编码解码往返一致性
    /// </summary>
    [Fact]
    public void AES_EncodeDecode_RoundTripsViaService()
    {
        var svc = new SecurityService(CryptoAlgorithm.AES, "my-key", iv: null);
        var plain = "测试 Test 123 🔒";
        var cipher = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(cipher));
    }

    /// <summary>
    /// 验证MD5算法的Encode返回哈希值，Decode抛出NotSupportedException
    /// </summary>
    [Fact]
    public void MD5_Encode_ReturnsHashAndDecode_Throws()
    {
        var svc = new SecurityService(CryptoAlgorithm.MD5, "ignored");
        Assert.Equal(MD5Helper.ComputeHash("hello"), svc.Encode("hello"));
        Assert.Throws<NotSupportedException>(() => svc.Decode("anything"));
    }

    /// <summary>
    /// 验证哈希算法（SHA256、SHA512、SM3）的Decode操作抛出NotSupportedException
    /// </summary>
    [Theory]
    [InlineData(CryptoAlgorithm.SHA256)]
    [InlineData(CryptoAlgorithm.SHA512)]
    [InlineData(CryptoAlgorithm.SM3)]
    public void HashAlgorithms_Decode_Throws(CryptoAlgorithm algorithm)
    {
        var svc = new SecurityService(algorithm, "ignored");
        Assert.Throws<NotSupportedException>(() => svc.Decode("anything"));
    }

    /// <summary>
    /// 验证Base64算法通过SecurityService的编码解码往返一致性
    /// </summary>
    [Fact]
    public void Base64_EncodeDecode_RoundTripsViaService()
    {
        var svc = new SecurityService(CryptoAlgorithm.Base64, "ignored");
        var plain = "测试 Test 123 🔒";
        var encoded = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(encoded));
    }

    /// <summary>
    /// 验证RSA算法通过SecurityService使用Key和Key2进行编码解码往返一致性
    /// </summary>
    [Fact]
    public void RSA_EncodeDecode_RoundTripsViaServiceUsingKeyAndKey2()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var svc = new SecurityService(CryptoAlgorithm.RSA, pub, priv);
        var plain = "RSA 测试 123";
        var cipher = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(cipher));
    }

    /// <summary>
    /// 验证RSA算法在未提供私钥时Decode操作抛出异常
    /// </summary>
    [Fact]
    public void RSA_Decode_ThrowsWhenNoPrivateKey()
    {
        var (pub, _) = RSAHelper.GenerateKeyPair();
        var svc = new SecurityService(CryptoAlgorithm.RSA, pub);
        Assert.ThrowsAny<ArgumentException>(() => svc.Decode(svc.Encode("data")));
    }

    /// <summary>
    /// 验证使用不支持的算法枚举值时Encode操作抛出NotSupportedException
    /// </summary>
    [Fact]
    public void Encode_UnsupportedAlgorithm_Throws()
    {
        var svc = new SecurityService((CryptoAlgorithm)999, "key");
        Assert.Throws<NotSupportedException>(() => svc.Encode("data"));
    }

    /// <summary>
    /// 验证对空或null内容进行编码时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encode_NullOrEmptyContent_Throws(string? content)
    {
        var svc = new SecurityService(CryptoAlgorithm.Base64, "ignored");
        Assert.ThrowsAny<ArgumentException>(() => svc.Encode(content!));
    }
}