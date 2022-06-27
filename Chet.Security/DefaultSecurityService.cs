namespace Chet.Security
{
    /// <summary>
    /// 默认加密服务
    /// </summary>
    public class DefaultSecurityService : ISecurityService
    {
        private readonly string key;
        private readonly string key2;

        /// <summary>
        /// 实例化加密服务
        /// </summary>
        /// <param name="algorithm">算法</param>
        /// <param name="key">密钥</param>
        /// <param name="key2">密钥2</param>
        public DefaultSecurityService(Algorithm algorithm, string key, string key2="")
        {
            Algorithm = algorithm;
            this.key = key;
            this.key2 = key2;
        }
        /// <summary>
        /// 加密算法
        /// </summary>
        public Algorithm Algorithm { get; }
        /// <summary>
        /// 对文本进行解密
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        public string Decode(string content)
        {
            switch (Algorithm)
            {
                case Algorithm.Aes:
                    return AES.DecryptText(content, key);
                case Algorithm.Des:
                    return Des.DesDecrypt(content, key);
                case Algorithm.TripDes:
                    return Des.TripDesDecrypt(content, key);
                case Algorithm.MD5:
                    throw new Exception("MD5算法不支持解密");
                case Algorithm.Rsa:
                    return RSA.DecryptByPrivateKey(content, key2);
                case Algorithm.Base64:
                    return Base64.Base64Decode(content, key);
                default:
                    return content;
            }
        }
        /// <summary>
        /// 对字节数组进行解密
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] bytes)
        {
            switch (Algorithm)
            {
                case Algorithm.Aes:
                    return AES.AESDecryptBytes(bytes, key);
                case Algorithm.Des:
                    return Des.Decrypt(bytes, key);
                case Algorithm.TripDes:  
                case Algorithm.Rsa: 
                case Algorithm.Base64:
                default: throw new NotImplementedException("尚未实现该算法的字节数组解密功能");
            }
        }
        /// <summary>
        /// 对文本进行加密
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        public string Encode(string content)
        {
            switch (Algorithm)
            {
                case Algorithm.Aes:
                    return AES.EncryptText(content, key);
                case Algorithm.Des:
                    return Des.DesEncrypt(content, key);
                case Algorithm.TripDes:
                    return Des.TripDesEncrypt(content, key);
                case Algorithm.MD5:
                    return MD5Utility.MD5Encrypt(content);
                case Algorithm.Rsa:
                    return RSA.EncryptTextByPublicKey(content, key);
                case Algorithm.Base64:
                    return Base64.Base64Encode(content, key);
                default:
                    return content;
            }
        }
        /// <summary>
        /// 对字节数组进行加密
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] bytes)
        {
            switch (Algorithm)
            {
                case Algorithm.Aes:
                    return AES.AESEncryptBytes(bytes, key);
                case Algorithm.Des:
                    return Des.Encrypt(bytes, key);
                case Algorithm.MD5:
                case Algorithm.TripDes:
                case Algorithm.Rsa:
                case Algorithm.Base64:
                default:
                    throw new NotImplementedException("尚未实现该算法的字节数组加密功能");
            }
        }
    }
}
