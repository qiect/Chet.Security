using System;
using System.IO;

namespace Chet.Security
{
    /// <summary>
    /// Base64编码、解码类
    /// </summary>
    public static class Base64
    {
        static string sBaseTable = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        #region BASE64编码函数

        /// <summary>
        /// 使用公用密钥的BASE64编码
        /// </summary>
        /// <param name="message">待编码字符串</param>
        /// <returns>编码后字符串</returns>
        public static string Base64Encode(string message)
        {            
            return Base64Encode(message, sBaseTable);           
        }

        /// <summary>
        /// 使用系统文本编码进行BASE64编码，兼容Delphi
        /// </summary>
        /// <param name="message">待编码字符串</param>
        /// <param name="baseTable">BASE64表</param>
        /// <returns></returns>
        public static string Base64Encode(string message, string baseTable)
        {
            return Base64Encode(message, baseTable, System.Text.Encoding.Default);
        }


        /// <summary>
        /// BASE64编码
        /// </summary>
        /// <param name="message">待编码字符串</param>
        /// <param name="baseTable">BASE64表</param>
        /// <param name="coding">文本编码</param>
        /// <returns>编码后字符串</returns>
        public static string Base64Encode(string message, string baseTable, System.Text.Encoding coding)
        {
            if (coding != null)
                return Base64EncodeEx(coding.GetBytes(message), baseTable);
            else
                return null;

        }

        /// <summary>
        /// BASE64编码,使用公用密钥对字节数组进行编码
        /// </summary>
        /// <param name="message">待编码字节数组</param>
        /// <returns>编码后字符串</returns>
        public static string Base64EncodeEx(byte[] message)
        {
            return Base64EncodeEx(message, sBaseTable);
        }

        /// <summary>
        /// BASE64编码,对文件进行编码
        /// </summary>
        /// <param name="filePath">待编码文件</param>
        /// <param name="baseTable">BASE64表</param>
        /// <returns>编码后字符串</returns>
        public static string Base64EncodeFile(string filePath, string baseTable)
        {
            if (!File.Exists(filePath)) throw new IOException("Base64EncodeFile发生错误，文件" + filePath + "不存在。");

            //使用900k的缓冲区进行读取和编码
            byte[] buffer = new byte[900];
            long iLeft = 0;
            //int iPos = 0;
            int iLen = 0;

            System.Text.StringBuilder sb = new System.Text.StringBuilder(900 * 4 / 3);
            try
            {
                //分块从文件读取并编码
                using (FileStream fs = new FileStream(filePath, System.IO.FileMode.Open))
                {
                    iLeft = fs.Length;
                    while (iLeft > 0)
                    {
                        if (iLeft >= buffer.Length)
                        {
                            iLen = buffer.Length;
                            fs.Read(buffer, 0, iLen);

                            //编码
                            sb.Append(Base64EncodeEx(buffer, baseTable));
                        }
                        else
                        {
                            iLen = (int)iLeft;
                            byte[] buffer1 = new byte[iLen];
                            fs.Read(buffer1, 0, iLen);

                            //编码
                            sb.Append(Base64EncodeEx(buffer1, baseTable));
                        }

                        iLeft -= iLen;
                        //iPos += iLen;
                    }
                }
                return sb.ToString();
            }
            finally
            {
                sb.Remove(0, sb.Length);
                //释放StringBuilder占用资源
                //GC.Collect(GC.GetGeneration(sb));
            }
        }


        /// <summary>
        /// BASE64编码,使用公用密钥对文件进行编码
        /// </summary>
        /// <param name="filePath">待编码文件</param>
        /// <returns>编码后字符串</returns>
        public static string Base64EncodeFile(string filePath)
        {
            
            return Base64EncodeFile(filePath, sBaseTable);
        }

        /// <summary>
        ///  BASE64编码,对字节数组进行编码
        /// </summary>
        /// <param name="message">待编码字节数组</param>
        /// <param name="baseTable">BASE64表</param>
        /// <returns>编码后字符串</returns>
        public static string Base64EncodeEx(byte[] message, string baseTable)
        {
            if (string.IsNullOrEmpty(baseTable)) return null;
            if (!baseTable.EndsWith("=")) baseTable += "=";
            if (baseTable.Length != 65)
                throw new Exception("Base64Encode函数发生错误：sBaseTable不是有效的BASE表,sBaseTable为" + baseTable);

            char[] Base64Code = baseTable.ToCharArray();
            byte empty = (byte)0;

            System.Collections.ArrayList byteMessage = new System.Collections.ArrayList(message);

            System.Text.StringBuilder outmessage;
            int messageLen = byteMessage.Count;
            int page = messageLen / 3;
            int use = 0;
            if ((use = messageLen % 3) > 0)
            {
                //剩下use个，需补充 (3-use)个
                for (int i = 0; i < 3 - use; i++)
                    byteMessage.Add(empty);
                page++;
            }
            outmessage = new System.Text.StringBuilder(page * 4);
            for (int i = 0; i < page; i++)
            {
                byte[] instr = new byte[3];
                instr[0] = (byte)byteMessage[i * 3];
                instr[1] = (byte)byteMessage[i * 3 + 1];
                instr[2] = (byte)byteMessage[i * 3 + 2];
                int[] outstr = new int[4];
                outstr[0] = instr[0] >> 2;
                outstr[1] = ((instr[0] & 0x03) << 4) ^ (instr[1] >> 4);
                if (use == 1 && (i == (page - 1)))
                    outstr[2] = 64;
                else
                    outstr[2] = ((instr[1] & 0x0f) << 2) ^ (instr[2] >> 6);
                if (use >= 1 && (i == (page - 1)))
                    outstr[3] = 64;
                else
                    outstr[3] = (instr[2] & 0x3f);

                outmessage.Append(Base64Code[outstr[0]]);
                outmessage.Append(Base64Code[outstr[1]]);
                outmessage.Append(Base64Code[outstr[2]]);
                outmessage.Append(Base64Code[outstr[3]]);
            }
            return outmessage.ToString();
        }


        /// <summary>
        /// 使用公用密钥的BASE64解码
        /// </summary>
        /// <param name="message">待解码字符串</param>
        /// <returns>解码后字符串</returns>
        public static string Base64Decode(string message)
        {
            
            return Base64Decode(message, sBaseTable);
        }


        /// <summary>
        /// BASE64解码
        /// </summary>
        /// <param name="message">待解码字符串</param>
        /// <param name="baseTable">BASE64表</param>	
        /// <returns>解码后字符串</returns>
        public static string Base64Decode(string message, string baseTable)
        {
            return Base64Decode(message, baseTable, System.Text.Encoding.Default);
        }


        /// <summary>
        /// BASE64解码
        /// </summary>
        /// <param name="message">待解码字符串</param>
        /// <param name="baseTable">BASE64表</param>
        /// <param name="coding">文本编码</param>
        /// <returns>解码后字符串</returns>
        public static string Base64Decode(string message, string baseTable, System.Text.Encoding coding)
        {
            if (coding != null)
                return coding.GetString(Base64DecodeEx(message, baseTable));
            else
                return null;
        }

        /// <summary>
        /// BASE64解码并返回字节数组
        /// </summary>
        /// <param name="message">待解码字符串</param>
        /// <param name="baseTable">BASE64表</param>
        /// <returns></returns>
        public static byte[] Base64DecodeEx(string message, string baseTable)
        {
            if (string.IsNullOrEmpty(message) || string.IsNullOrEmpty(baseTable)) return null;

            if ((message.Length % 4) != 0)
            {
                throw new ArgumentException("不是正确的BASE64编码，请检查。", message);
            }
            if (!System.Text.RegularExpressions.Regex.IsMatch(message, "^[A-Z0-9/+=]*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            {
                throw new ArgumentException("包含不正确的BASE64编码，请检查。", message);
            }
            bool b1 = true, b2 = true;
            if (!baseTable.EndsWith("=")) baseTable += "=";

            string Base64Code = baseTable;
            int page = message.Length / 4;
            System.Collections.ArrayList outMessage = new System.Collections.ArrayList(page * 3);
            char[] cMessage = message.ToCharArray();
            for (int i = 0; i < page; i++)
            {
                byte[] instr = new byte[4];
                instr[0] = (byte)Base64Code.IndexOf(cMessage[i * 4]);
                instr[1] = (byte)Base64Code.IndexOf(cMessage[i * 4 + 1]);
                instr[2] = (byte)Base64Code.IndexOf(cMessage[i * 4 + 2]);
                instr[3] = (byte)Base64Code.IndexOf(cMessage[i * 4 + 3]);
                byte[] outstr = new byte[3];
                outstr[0] = (byte)((instr[0] << 2) ^ ((instr[1] & 0x30) >> 4));
                if (instr[2] != 64)
                {
                    b1 = true;
                    outstr[1] = (byte)((instr[1] << 4) ^ ((instr[2] & 0x3c) >> 2));
                }
                else
                {
                    b1 = false;
                    outstr[1] = 0;
                }
                if (instr[3] != 64)
                {
                    b2 = true;
                    outstr[2] = (byte)((instr[2] << 6) ^ instr[3]);
                }
                else
                {
                    b2 = false;
                    outstr[2] = 0;
                }
                outMessage.Add(outstr[0]);
                if (b1)
                    outMessage.Add(outstr[1]);
                if (b2)
                    outMessage.Add(outstr[2]);
            }
            byte[] outbyte = (byte[])outMessage.ToArray(Type.GetType("System.Byte"));
            return outbyte;

        }


        /// <summary>
        /// 使用公用密钥进行BASE64解码并返回字节数组
        /// </summary>
        /// <param name="message">待解码字符串</param>
        /// <returns></returns>
        public static byte[] Base64DecodeEx(string message)
        {            
            return Base64DecodeEx(message, sBaseTable);
        }


        #endregion
    }
}
