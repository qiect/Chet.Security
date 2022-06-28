using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Chet.Security
{
    /// <summary>
    /// Des加解密辅助类
    /// ndf平台使用的Des密钥长度为8位
    /// </summary>
    public static class Des
    {
        static string DesTable = @"B1234567";

        #region Des  
        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="toEncrypt">被加密字符串</param>
        /// <returns></returns>
        public static string DesEncrypt(string toEncrypt)
        {
            return DesEncrypt(toEncrypt, DesTable);
        }

        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="toEncrypt">被加密字符串</param>
        /// <param name="key">Des key</param>
        /// <returns></returns>
        public static string DesEncrypt(string toEncrypt, string key)
        {
            var resultBytes = Encrypt(Encoding.Default.GetBytes(toEncrypt), key);
            StringBuilder ret = new StringBuilder();
            foreach (byte b in resultBytes)
            {
                ret.AppendFormat("{0:X2}", b);
            }
            return ret.ToString();
        }
        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="toEncrypt"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] toEncrypt, string key = "")
        {
            if (string.IsNullOrEmpty(key)) key = DesTable;
            var des = new DESCryptoServiceProvider();
            des.Key = Encoding.ASCII.GetBytes(key);
            des.IV = Encoding.ASCII.GetBytes(key);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(toEncrypt, 0, toEncrypt.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }


        /// <summary>
        /// DES解密
        /// </summary>
        /// <param name="toDecrypt">被解密字符串</param>
        /// <returns></returns>
        public static string DesDecrypt(string toDecrypt)
        {
            return DesDecrypt(toDecrypt, DesTable);
        }

        /// <summary>
        /// DES解密
        /// </summary>
        /// <param name="toDecrypt">被解密字符串</param>
        /// <param name="sKey">Des key</param>
        /// <returns></returns>
        public static string DesDecrypt(string toDecrypt, string sKey)
        {
            if (string.IsNullOrEmpty(toDecrypt)) return null;
            byte[] inputByteArray = new byte[toDecrypt.Length / 2];
            for (int x = 0; x < toDecrypt.Length / 2; x++)
            {
                int i = (Convert.ToInt32(toDecrypt.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            }
            var resultBytes = Decrypt(inputByteArray, sKey);
            return Encoding.Default.GetString(resultBytes);
        }
        /// <summary>
        /// des解密
        /// </summary>
        /// <param name="toEncrypt"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] toEncrypt, string key = "")
        {
            if (string.IsNullOrEmpty(key)) key = DesTable;
            var des = new DESCryptoServiceProvider();
            des.Key = Encoding.ASCII.GetBytes(key);
            des.IV = Encoding.ASCII.GetBytes(key);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(toEncrypt, 0, toEncrypt.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }
        #endregion

        #region  TripDes
        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="toEncrypt">被加密字符串</param>
        /// <returns></returns>
        public static string TripDesEncrypt(string toEncrypt)
        {
            return TripDesEncrypt(toEncrypt, DesTable);

        }

        /// <summary>
        /// TripDES加密
        /// </summary>
        /// <param name="toEncrypt">被加密字符串</param>
        /// <param name="key">Des key</param>
        /// <returns></returns>
        public static string TripDesEncrypt(string toEncrypt, string key)
        {
            Byte[] plainText = Encoding.UTF8.GetBytes(toEncrypt);
            byte[] encrypted;
            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = Encoding.UTF8.GetBytes(MD5Utility.MD5Encrypt(key).Substring(0, 24));
                tdsAlg.IV = Encoding.UTF8.GetBytes(key);
                ICryptoTransform encryptor = tdsAlg.CreateEncryptor(tdsAlg.Key, tdsAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainText, 0, plainText.Length);
                        csEncrypt.FlushFinalBlock();
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            StringBuilder ret = new StringBuilder();
            foreach (byte b in encrypted.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            return ret.ToString();
        }

        /// <summary>
        /// TripDES解密
        /// </summary>
        /// <param name="toDecrypt">被解密字符串</param>
        /// <returns></returns>
        public static string TripDesDecrypt(string toDecrypt)
        {
            return TripDesDecrypt(toDecrypt, DesTable);
        }

        /// <summary>
        /// TripDES解密
        /// </summary>
        /// <param name="toDecrypt">被解密字符串</param>
        /// <param name="key">Des key</param>
        /// <returns></returns>
        public static string TripDesDecrypt(string toDecrypt, string key)
        {
            if (string.IsNullOrEmpty(toDecrypt)) return null;
            byte[] inputByteArray = new byte[toDecrypt.Length / 2];
            for (int x = 0; x < toDecrypt.Length / 2; x++)
            {
                int i = (Convert.ToInt32(toDecrypt.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            }
            string plaintext = null;
            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = Encoding.UTF8.GetBytes(MD5Utility.MD5Encrypt(key).Substring(0, 24));
                tdsAlg.IV = Encoding.UTF8.GetBytes(key);
                ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(inputByteArray))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        #endregion
    }
}
