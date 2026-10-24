using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

public class SM2HelperTests
{
    [Fact]
    public void GenerateKeyPair_ReturnsNonEmptyBase64Keys()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        Assert.False(string.IsNullOrEmpty(pub));
        Assert.False(string.IsNullOrEmpty(priv));
        // Public key: 65 bytes uncompressed point -> 88 base64 chars (no padding).
        Assert.Equal(65, Convert.FromBase64String(pub).Length);
        // Private key: 32 byte scalar -> 44 base64 chars (no padding).
        Assert.Equal(32, Convert.FromBase64String(priv).Length);
    }

    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var plain = "SM2 测试 123";
        var cipher = SM2Helper.Encrypt(plain, pub);
        Assert.Equal(plain, SM2Helper.Decrypt(cipher, priv));
    }

    [Fact]
    public void EncryptDecrypt_Unicode_RoundTrips()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var plain = "测试 Test 123 🔒";
        var cipher = SM2Helper.Encrypt(plain, pub);
        Assert.Equal(plain, SM2Helper.Decrypt(cipher, priv));
    }

    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = SM2Helper.Sign(data, priv);
        Assert.True(SM2Helper.Verify(data, signature, pub));
    }

    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var signature = SM2Helper.Sign("original-data", priv);
        Assert.False(SM2Helper.Verify("tampered-data", signature, pub));
    }

    [Fact]
    public void Encrypt_DiffersFromPlaintext()
    {
        var (pub, _) = SM2Helper.GenerateKeyPair();
        var cipher = SM2Helper.Encrypt("data", pub);
        Assert.NotEqual("data", cipher);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => SM2Helper.Encrypt(plain!, "public-key"));
    }
}
