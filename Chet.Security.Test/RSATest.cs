using NUnit.Framework;
using System.Linq;

namespace Chet.Security.Test
{
    public class RSATest
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void EncryptTest()
        {
            var key = RSA.GetKey();
            var strText = "chet.security";
            var encryptText = RSA.EncryptTextByPublicKey(strText, key.PublicKey);
            var decryptText = RSA.DecryptByPrivateKey(encryptText, key.PrivateKey);
            Assert.AreEqual(strText, decryptText);
        }

        [Test]
        public void EncryptLongTextTest()
        {
            var key = RSA.GetKey();
            var strText = "chet.security;";
            Enumerable.Range(0, 10).ToList().ForEach(p => strText += strText);
            var encryptText = RSA.EncryptLongTextByPublicKey(strText, key.PublicKey);
            var decryptText = RSA.DecryptLongTextByPrivateKey(encryptText, key.PrivateKey);
            Assert.AreEqual(strText, decryptText);
        }
    }
}