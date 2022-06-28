using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Chet.Security
{
    /// <summary>
    /// AES编码、解码类
    /// 模式（AES/CBC/PKCS7）
    /// </summary>
    public static class AES
    {
        #region 加密
        /// <summary>
        /// 使用指定的key对输入文本进行加密
        /// </summary>
        /// <param name="input">输入文本</param>
        /// <param name="key">密钥</param>
        /// <returns></returns>
        public static string EncryptText(string input, string key)
        {
            if (string.IsNullOrEmpty(input)) { return ""; }
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] bytesEncrypted = AESEncryptBytes(bytesToBeEncrypted, key);
            string result = Convert.ToBase64String(bytesEncrypted);
            return result;
        }
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="bytesToBeEncrypted"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] AESEncryptBytes(byte[] bytesToBeEncrypted, string key="")
        {
            byte[] passwordBytes = SecurityHelper.CreateKeyByte(key, KeyTransMode.Md5, 128);
            byte[] encryptedBytes = null;
            using (var ms = new MemoryStream())
            {
                using (var AES = new RijndaelManaged())
                {
                    AES.Key = passwordBytes;
                    AES.IV = passwordBytes;
                    AES.Mode = CipherMode.CBC;
                    AES.Padding = PaddingMode.PKCS7;
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }
        #endregion

        #region 解密
        /// <summary>
        /// 使用指定的key对密文解密
        /// </summary>
        /// <param name="input">密文</param>
        /// <param name="key">密钥</param>
        /// <returns></returns>
        public static string DecryptText(string input, string key)
        {
            byte[] toEncryptArray = Convert.FromBase64String(input);
            return UTF8Encoding.UTF8.GetString(AESDecryptBytes(toEncryptArray, key)).Replace("\0", "");
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] AESDecryptBytes(byte[] bytes, string key="")
        {
            byte[] passwordBytes = SecurityHelper.CreateKeyByte(key, KeyTransMode.Md5, 128);
            using (var AES = new RijndaelManaged())
            {
                AES.Key = passwordBytes;
                AES.IV = passwordBytes;
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;
                ICryptoTransform cTransform = AES.CreateDecryptor();
                byte[] result = cTransform.TransformFinalBlock(bytes, 0, bytes.Length);
                return result;
            }
        }

        #endregion
    }
}
