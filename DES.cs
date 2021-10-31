using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
namespace DESsifreleme
{
   public class DES
    {
        public const string hash = "fUrqEm";
        public string Sifrele(string metin)
        {
            
            byte[] veri = UTF8Encoding.UTF8.GetBytes(metin);
            using(MD5CryptoServiceProvider md5=new MD5CryptoServiceProvider())
            {
                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(hash));
                
                using(TripleDESCryptoServiceProvider tripleDES=new TripleDESCryptoServiceProvider())
                {
                    tripleDES.Key = keys;
                    tripleDES.Mode = CipherMode.ECB;
                    tripleDES.Padding = PaddingMode.PKCS7;
                    ICryptoTransform transform = tripleDES.CreateEncryptor();
                    byte[] result = transform.TransformFinalBlock(veri, 0, veri.Length);
                    return Convert.ToBase64String(result);
                }
            }
        }

        public string SifreCoz(string Sifrelimetin)
        {
            byte[] veri = Convert.FromBase64String(Sifrelimetin);
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(hash));

                using (TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider())
                {
                    tripleDES.Key = keys;
                    tripleDES.Mode = CipherMode.ECB;
                    tripleDES.Padding = PaddingMode.PKCS7;
                    ICryptoTransform transform = tripleDES.CreateDecryptor();
                    byte[] result = transform.TransformFinalBlock(veri, 0, veri.Length);
                    return UTF8Encoding.UTF8.GetString(result);
                }
            }
        }
    }
}
