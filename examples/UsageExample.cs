using System;
using Chet.Security;
using System.Text;

class UsageExample
{
    static void Main()
    {
        // MD5
        var md5Hex = MD5Util.ComputeHashHex("hello world");
        Console.WriteLine($"MD5(hello world) = {md5Hex}");

        // Base64
        var encoded = Base64Util.EncodeToString("hello qiect");
        var decoded = Base64Util.DecodeToString(encoded);
        Console.WriteLine($"Base64 encode: {encoded}");
        Console.WriteLine($"Base64 decode: {decoded}");

        // AES 示例（请确保 key/iv 长度符合实现要求，例如 16 字节）
        string aesKey = "0123456789abcdef"; // 16 chars => 128-bit
        string aesIv  = "abcdef9876543210"; // 16 chars
        string plain = "Sensitive data";
        string aesCipher = AESUtil.EncryptStringToBase64(plain, aesKey, aesIv);
        string aesPlain  = AESUtil.DecryptStringFromBase64(aesCipher, aesKey, aesIv);
        Console.WriteLine($"AES cipher (base64): {aesCipher}");
        Console.WriteLine($"AES decrypted: {aesPlain}");

        // RSA 示例
        var (publicPem, privatePem) = RSAUtil.GenerateKeyPair(2048);
        var rsaCipher = RSAUtil.EncryptWithPublic("Top Secret", publicPem);
        var rsaPlain  = RSAUtil.DecryptWithPrivate(rsaCipher, privatePem);
        Console.WriteLine($"RSA plain: {rsaPlain}");

        // RSA 签名/验签
        string message = "Important message";
        string signature = RSAUtil.SignData(message, privatePem);
        bool verified = RSAUtil.VerifySignature(message, signature, publicPem);
        Console.WriteLine($"Signature verified: {verified}");
    }
}
