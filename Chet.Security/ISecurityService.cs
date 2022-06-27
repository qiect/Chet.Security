using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chet.Security
{
    /// <summary>
    /// 加密算法
    /// </summary>
    public enum Algorithm : int
    {
        /// <summary>
        /// MD5，信息摘要算法
        /// </summary>
        MD5 = 1,
        /// <summary>
        /// AES，对称加密算法
        /// </summary>
        Aes = 2,
        /// <summary>
        /// Des，对称加密算法，已经被AES替代
        /// </summary>
        Des = 3,
        /// <summary>
        /// TripDes，3级DES算法, 是DES的升级版
        /// </summary>
        TripDes = 4,
        /// <summary>
        /// Rsa，非对称加密算法
        /// </summary>
        Rsa = 5,
        /// <summary>
        /// Base64，文件编码算法
        /// </summary>
        Base64 = 6,
    }

    /// <summary>
    /// 加密服务接口
    /// </summary>
    public interface ISecurityService
    {
        /// <summary>
        /// 加密算法
        /// </summary>
        Algorithm Algorithm { get; }
        /// <summary>
        /// 加密文本
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        string Encode(string content);
        /// <summary>
        /// 解密文本
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        string Decode(string content);
        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        byte[] Encrypt(byte[] bytes);
        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        byte[] Decrypt(byte[] bytes);
    }
}
