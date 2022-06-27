using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Text;

namespace Chet.Security
{
    /// <summary>
    /// RSA编码、解码类
    /// 使用此类需要引用Portable.BouncyCastle包，实现跨平台的加解密一致性
    /// </summary>
    public static class RSA
    {
        /// <summary>
        /// 分割长度
        /// </summary>
        private static int splitLength = 30;
        /// <summary>
        /// 分隔符
        /// </summary>
        private static string delimiter = "|||";

        /// <summary>
        /// 生成公钥和私钥对（Base64）
        /// </summary>
        /// <returns></returns>
        public static RSAKEY GetKey()
        {
            //RSA密钥对的构造器  
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();

            //RSA密钥构造器的参数  
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(3),
                new SecureRandom(),
                1024,   //密钥长度  
                25);
            //用参数初始化密钥构造器  
            keyGenerator.Init(param);
            //产生密钥对  
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            //获取公钥和密钥  
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);


            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded("UTF-8");

            RSAKEY item = new RSAKEY()
            {
                PublicKey = Convert.ToBase64String(publicInfoByte),
                PrivateKey = Convert.ToBase64String(privateInfoByte)
            };
            return item;
        }

        #region 加密
        /// <summary>
        /// 使用公钥对输入内容进行加密
        /// </summary>
        /// <param name="input">输入文本</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static string EncryptTextByPublicKey(string strText, string publicKey)
        {
            if (string.IsNullOrEmpty(strText)) { return ""; }
            var rsa = CreateRsaProviderFromPublicKey(publicKey);
            string encryptedData = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(strText), false));
            return encryptedData;
        }
        /// <summary>
        /// 使用私钥对输入内容进行加密
        /// </summary>
        /// <param name="input">输入文本</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static string EncryptTextByPrivateKey(string strText, string privateKey)
        {
            if (string.IsNullOrEmpty(strText)) { return ""; }
            var rsa = CreateRsaProviderFromPublicKey(privateKey);
            string encryptedData = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(strText), false));
            return encryptedData;
        }
        /// <summary>
        /// 通过公钥加密（长文本）
        /// </summary>
        /// <param name="strText"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string EncryptLongTextByPublicKey(string strText, string publicKey)
        {
            string plainTextBArray;
            string cypherTextBArray;
            string Result = String.Empty;
            var rsa = CreateRsaProviderFromPublicKey(publicKey);
            int t = (int)Math.Ceiling((double)strText.Length / splitLength);
            //分割明文
            for (int i = 0; i <= t - 1; i++)
            {
                plainTextBArray = strText.Substring(i * splitLength, strText.Length - (i * splitLength) > splitLength ? splitLength : strText.Length - (i * splitLength));
                cypherTextBArray = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(plainTextBArray), false));
                Result += cypherTextBArray + "ThisIsSplit";
            }
            return Result;
        }
        /// <summary>
        /// 通过私钥加密（长文本）
        /// </summary>
        /// <param name="strText"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string EncryptLongTextByPrivateKey(string strText, string privateKey)
        {
            string plainTextBArray;
            string cypherTextBArray;
            string Result = String.Empty;
            var rsa = CreateRsaProviderFromPrivateKey(privateKey);
            int t = (int)Math.Ceiling((double)strText.Length / splitLength);
            //分割明文
            for (int i = 0; i <= t - 1; i++)
            {
                plainTextBArray = strText.Substring(i * splitLength, strText.Length - (i * splitLength) > splitLength ? splitLength : strText.Length - (i * splitLength));
                cypherTextBArray = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(plainTextBArray), false));
                Result += cypherTextBArray + "ThisIsSplit";
            }
            return Result;
        }



        private static RSACryptoServiceProvider CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKeyString));
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAKeyInfo = new RSAParameters();
            RSAKeyInfo.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            RSAKeyInfo.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            RSA.ImportParameters(RSAKeyInfo);
            return RSA;
        }
        #endregion

        #region 解密
        /// <summary>
        /// 使用私钥对密文进行解密
        /// </summary>
        /// <param name="input"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>

        public static string DecryptByPrivateKey(string decryptString, string privateKey)
        {
            var rsa = CreateRsaProviderFromPrivateKey(privateKey);
            string plainText = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(decryptString), false));
            return plainText;
        }
        /// <summary>
        /// 使用公钥对密文进行解密
        /// </summary>
        /// <param name="input"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>

        public static string DecryptByPublicKey(string decryptString, string publicKey)
        {
            var rsa = CreateRsaProviderFromPrivateKey(publicKey);
            string plainText = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(decryptString), false));
            return plainText;
        }


        /// <summary>
        /// 使用私钥对密文进行解密（长文本）
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="decryptString">密文</param>
        /// <returns>明文</returns>
        public static string DecryptLongTextByPrivateKey(string decryptString, string privateKey)
        {
            string result = String.Empty;
            var rsa = CreateRsaProviderFromPrivateKey(privateKey);
            string[] split = new string[1];
            split[0] = "ThisIsSplit";
            //分割密文
            string[] strs = decryptString.Split(split, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < strs.Length; i++)
            {
                //解密
                result += Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(strs[i]), false));
            }
            return result;
        }

        /// <summary>
        /// 使用公钥对密文进行解密（长文本）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="decryptString">密文</param>
        /// <returns>明文</returns>
        public static string DecryptLongTextByPublicKey(string decryptString, string publicKey)
        {
            string result = String.Empty;
            var rsa = CreateRsaProviderFromPublicKey(publicKey);
            string[] split = new string[1];
            split[0] = "ThisIsSplit";
            //分割密文
            string[] strs = decryptString.Split(split, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < strs.Length; i++)
            {
                //解密
                var baseStr = Convert.FromBase64String(strs[i]);
                var sf = rsa.Decrypt(baseStr, false);
                result += Encoding.UTF8.GetString(sf);
            }
            return result;
        }

        private static RSACryptoServiceProvider CreateRsaProviderFromPrivateKey(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            RSAParameters parameters = new RSAParameters();
            parameters.Modulus = privateKeyParam.Modulus.ToByteArrayUnsigned();
            parameters.Exponent = privateKeyParam.PublicExponent.ToByteArrayUnsigned();
            parameters.P = privateKeyParam.P.ToByteArrayUnsigned();
            parameters.Q = privateKeyParam.Q.ToByteArrayUnsigned();
            parameters.DP = privateKeyParam.DP.ToByteArrayUnsigned();
            parameters.DQ = privateKeyParam.DQ.ToByteArrayUnsigned();
            parameters.InverseQ = privateKeyParam.QInv.ToByteArrayUnsigned();
            parameters.D = privateKeyParam.Exponent.ToByteArrayUnsigned();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);
            return rsa;
        }
        #endregion


    }

    /// <summary>
    /// KEY 结构体
    /// </summary>
    public struct RSAKEY
    {
        /// <summary>
        /// 公钥
        /// </summary>
        public string PublicKey { get; set; }
        /// <summary>
        /// 私钥
        /// </summary>
        public string PrivateKey { get; set; }
    }
}
