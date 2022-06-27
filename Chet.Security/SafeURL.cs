using System.ComponentModel;

namespace Chet.Security
{
    /// <summary>
    ///功能：从安全性的角度出发，为了防止用户通过浏览器中URL的方式破解相关数据信息，有可能对网站发起攻击。 <br/>
    ///<br/>
    ///举例：传统Web前端跟后端传递信息的方式譬如浏览器中URL为：<br/>
    ///<![CDATA[ http://localhost:11261/ADRSJT2013QUERY/ViewProjStateData/RStateFrame.aspx?IUKID=2013001&filePath=BRA.Cll&sModuleCode=R]]>
    ///<br/>  
    /// 从上面的链接当中可以很容易获取以下信息：<br/>
    ///     IUKID=2013001；filePath=BRA.Cll；sModuleCode=R<br/>
    ///     所以出于安全角度的考虑需要将上面字符"?"后面的参数进行加密。<br/>
    ///     例如可以将上例中的参数传递字符串IUKID=2013001;filePath=BRA.Cll;sModuleCode=R加密之后的字符串为<br/>
    ///     B9A1CB7BE080617E9E82049C7254B9E8B72655781ECBE2649F3ABC55320561A80E242612C421305A915509827B1C7461<br/>
    ///     传递到后台之后，再进行解密分割字符串即可获得各个参数的值。<br/>
    /// </summary>
    public static class SafeUrl
    {
        /// <summary>
        /// 从以分号字符";"做分割的参数串[明文]中获取指定参数名称的参数值
        /// </summary>
        /// <param name="paraStr">参数字符串,明文的形式</param>
        /// <param name="paraName">参数名称</param>
        /// <returns>参数值，找不到则为null</returns>
        public static string GetUrlParam(string paraStr, string paraName)
        {
            if (String.IsNullOrEmpty(paraStr))
                return null;

            if (String.IsNullOrEmpty(paraName))
                return null;

            string s = "";
            int iStart = -1;

            try
            {
                string[] sParamList = paraStr.Split(';');

                for (int i = 0; i < sParamList.Length; i++)
                {
                    s = sParamList[i].ToString();
                    iStart = s.ToUpper().IndexOf(paraName.ToUpper() + "=");

                    if (iStart >= 0)
                        return s.Substring(paraName.Length + 1);
                }
                return null;
            }
            catch 
            {
                return null;
            }
        }

        /// <summary>
        /// 加密参数串
        /// </summary>
        /// <param name="paraStr">参数串,明文的形式</param>
        /// <param name="enableEncrypt">是否需要加密</param>
        /// <returns>返回设置之后的参数串</returns>
        
        public static string SetUrlParam(string paraStr, Boolean enableEncrypt)
        {
            if (String.IsNullOrEmpty(paraStr))
                return null;

			if (paraStr.Contains("&"))
			{
				paraStr = paraStr.Replace("&",";");
			}

            if (enableEncrypt == true)
            {
                return Chet.Security.Des.TripDesEncrypt(paraStr);
            }
            else
            {
                return paraStr;
            }
        }

        /// <summary>
        /// 将存储在匿名对象o里面的参数和值的组合追加到sParamString里面
        /// </summary>
        /// <example>
        /// <code>
        /// string s;
        /// var anoymousObj = new { id = 1, name = "aaa" };
        /// s.SetUrlParam(anoymousObj, true);
        /// </code>
        /// </example>
        /// <param name="paraStr">参数串,明文的形式</param>
        /// <param name="anoymousObj">参数和对应值的匿名对象</param>
        /// <param name="enableEncrypt">是否需要加密</param>
        /// <returns>返回设置之后的参数串</returns>
        public static string SetUrlParam(this string paraStr, Object anoymousObj, Boolean enableEncrypt)
        {
            foreach (PropertyDescriptor descriptor in TypeDescriptor.GetProperties(anoymousObj))
            {
                if (paraStr.Length == 0)
                {
                    paraStr = descriptor.Name + "=" + descriptor.GetValue(anoymousObj);
                }
                else
                {
                    paraStr = paraStr + ";" + descriptor.Name + "=" + descriptor.GetValue(anoymousObj); //id=1;name=aaa
                }
            }

            //根据bEnableEncrypt布尔值选择是否进行加密
            if (enableEncrypt == true)
            {
                return Chet.Security.Des.TripDesEncrypt(paraStr);
            }
            else
            {
                return paraStr;
            }
        }
    }
}
