using Chet.Security;
using Xunit;

namespace Chet.Security.Tests;

public class SecurityServiceTests
{
    [Fact]
    public void Constructor_SetsAlgorithmAndKeys()
    {
        var svc = new SecurityService(CryptoAlgorithm.AES, "key", "priv", "iv");
        Assert.Equal(CryptoAlgorithm.AES, svc.Algorithm);
        Assert.Equal("key", svc.Key);
        Assert.Equal("priv", svc.Key2);
        Assert.Equal("iv", svc.Iv);
    }

    [Fact]
    public void AES_EncodeDecode_RoundTripsViaService()
    {
        var svc = new SecurityService(CryptoAlgorithm.AES, "my-key", iv: null);
        var plain = "测试 Test 123 🔒";
        var cipher = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(cipher));
    }

    [Fact]
    public void MD5_Encode_ReturnsHashAndDecode_Throws()
    {
        var svc = new SecurityService(CryptoAlgorithm.MD5, "ignored");
        Assert.Equal(MD5Helper.ComputeHash("hello"), svc.Encode("hello"));
        Assert.Throws<NotSupportedException>(() => svc.Decode("anything"));
    }

    [Theory]
    [InlineData(CryptoAlgorithm.SHA256)]
    [InlineData(CryptoAlgorithm.SHA512)]
    [InlineData(CryptoAlgorithm.SM3)]
    public void HashAlgorithms_Decode_Throws(CryptoAlgorithm algorithm)
    {
        var svc = new SecurityService(algorithm, "ignored");
        Assert.Throws<NotSupportedException>(() => svc.Decode("anything"));
    }

    [Fact]
    public void Base64_EncodeDecode_RoundTripsViaService()
    {
        var svc = new SecurityService(CryptoAlgorithm.Base64, "ignored");
        var plain = "测试 Test 123 🔒";
        var encoded = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(encoded));
    }

    [Fact]
    public void RSA_EncodeDecode_RoundTripsViaServiceUsingKeyAndKey2()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var svc = new SecurityService(CryptoAlgorithm.RSA, pub, priv);
        var plain = "RSA 测试 123";
        var cipher = svc.Encode(plain);
        Assert.Equal(plain, svc.Decode(cipher));
    }

    [Fact]
    public void RSA_Decode_ThrowsWhenNoPrivateKey()
    {
        var (pub, _) = RSAHelper.GenerateKeyPair();
        var svc = new SecurityService(CryptoAlgorithm.RSA, pub);
        Assert.ThrowsAny<ArgumentException>(() => svc.Decode(svc.Encode("data")));
    }

    [Fact]
    public void Encode_UnsupportedAlgorithm_Throws()
    {
        var svc = new SecurityService((CryptoAlgorithm)999, "key");
        Assert.Throws<NotSupportedException>(() => svc.Encode("data"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encode_NullOrEmptyContent_Throws(string? content)
    {
        var svc = new SecurityService(CryptoAlgorithm.Base64, "ignored");
        Assert.ThrowsAny<ArgumentException>(() => svc.Encode(content!));
    }
}
