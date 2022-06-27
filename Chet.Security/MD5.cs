using System.Security.Cryptography;
using System.Text;

namespace Chet.Security
{
    /// <summary>
    /// MD5加密辅助类
    /// </summary>
    public static class MD5Utility
    {
        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="value">被加密字符串</param>
        /// <returns></returns>
        public static string MD5Encrypt(string value)
        {
            string pwd = "";
            MD5 md5 = MD5.Create();
            byte[] s = md5.ComputeHash(Encoding.UTF8.GetBytes(value));
            for (int i = 0; i < s.Length; i++)
            {
                string ss= s[i].ToString("X2");   
                pwd = pwd + ss;
            }
            return pwd;
        }


        /// <summary>
        /// 获取文件的MD5特征码
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns></returns>
        public static string GetMD5FileHash(string filePath)
        {
            string result = string.Empty;
            if (!File.Exists(filePath)) return result;

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                HashAlgorithm algorithm = MD5.Create();
                byte[] hashBytes = algorithm.ComputeHash(fs);
                result = System.BitConverter.ToString(hashBytes).Replace("-", "");
            }
            return result;
        }
    }
}
