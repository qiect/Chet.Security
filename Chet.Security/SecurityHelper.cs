using System;
using System.Collections.Generic;
using System.Text;

namespace Chet.Security
{
    /// <summary>
    /// 密钥补全模式
    /// </summary>
    public enum KeyTransMode
    {
        /// <summary>
        /// 对现有密钥进行MD5编码
        /// </summary>
        Md5,
        /// <summary>
        /// 对现有密钥进行右侧补0
        /// </summary>
        AddZero,
        /// <summary>
        /// 对现有密钥进行左侧补0
        /// </summary>
        AddZeroLeft
    }
    /// <summary>
    /// 加解密辅助方法
    /// </summary>
    public static class SecurityHelper
    {
        /// <summary>
        /// 将用户提供的密钥转换为加密算法要求的字节数组
        /// </summary>
        /// <param name="key">原始密钥</param>
        /// <param name="mode">密钥转换模式</param>
        /// <param name="length">密钥长度，通常情况为128和256</param>
        /// <returns></returns>
        public static byte[] CreateKeyByte(string key, KeyTransMode mode = KeyTransMode.Md5, int length = 256)
        {
            int start = 0;
            int count = length / 8;
            var keyBytes = new byte[count];
            if (mode == KeyTransMode.Md5)
            {
                key = Chet.Security.MD5Utility.MD5Encrypt(key);
                if (count == 16)
                {
                    key = key.Substring(8, 16);
                }
            }
            if (key.Length < count)
            {
                if (mode == KeyTransMode.AddZeroLeft)
                {
                    start = count - key.Length;
                }
                count = key.Length;
            }
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(key), 0, keyBytes, start, count);
            return keyBytes;
        }
    }
}
