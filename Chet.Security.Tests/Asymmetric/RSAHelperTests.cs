using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

public class RSAHelperTests
{
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    [Fact]
    public void GenerateKeyPair_InvalidKeySize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RSAHelper.GenerateKeyPair(100));
    }

    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = "RSA 测试 123";
        var cipher = RSAHelper.Encrypt(plain, pub);
        Assert.Equal(plain, RSAHelper.Decrypt(cipher, priv));
    }

    [Fact]
    public void EncryptDecrypt_Unicode_RoundTrips()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = "测试 Test 123 🔒";
        var cipher = RSAHelper.Encrypt(plain, pub);
        Assert.Equal(plain, RSAHelper.Decrypt(cipher, priv));
    }

    [Fact]
    public void EncryptLong_DecryptLong_RoundTripsOnLongText()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = new string('A', 500) + "测试 tail";
        var cipher = RSAHelper.EncryptLong(plain, pub);
        Assert.Equal(plain, RSAHelper.DecryptLong(cipher, priv));
    }

    [Fact]
    public void SignData_VerifyData_Succeeds()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = RSAHelper.SignData(data, priv);
        Assert.True(RSAHelper.VerifyData(data, signature, pub));
    }

    [Fact]
    public void VerifyData_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var signature = RSAHelper.SignData("original-data", priv);
        Assert.False(RSAHelper.VerifyData("tampered-data", signature, pub));
    }

    [Fact]
    public void Encrypt_WithPrivateKeyPemAsPublic_Throws()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        Assert.ThrowsAny<CryptographicException>(() => RSAHelper.Encrypt("data", priv));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => RSAHelper.Encrypt(plain!, "public-key-pem"));
    }
}
