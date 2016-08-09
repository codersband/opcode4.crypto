using System.IO;
using System.Security.Cryptography;
using System.Text;
using opcode4.utilities;

namespace opcode4.crypto
{
    public class TripleDES
    {
        private readonly TripleDESCryptoServiceProvider m_des = new TripleDESCryptoServiceProvider();
        private readonly byte[] m_key;
        private readonly byte[] m_iv;

        public TripleDES(byte[] key, byte[] iv)
        {
            m_key = key;
            m_iv = iv;
        }

        public byte[] Encrypt(byte[] input)
        {
            return Transform(input, m_des.CreateEncryptor(m_key, m_iv));
        }

        public byte[] Decrypt(byte[] input)
        {
            return Transform(input, m_des.CreateDecryptor(m_key, m_iv));
        }

        public string EncryptString(string text)
        {
            return Base64.EncodeBase64(Encrypt(Encoding.UTF8.GetBytes(text)));
        }

        public string DecryptString(string text)
        {
            return Encoding.UTF8.GetString(Decrypt(Base64.DecodeBase64(text)));
        }

        private static byte[] Transform(byte[] input, ICryptoTransform cryptoTransform)
        {
            using (var memStream = new MemoryStream())
            {
                using (var cryptStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptStream.Write(input, 0, input.Length);
                    cryptStream.FlushFinalBlock();
                    memStream.Position = 0;
                    var result = memStream.ToArray();

                    memStream.Close();
                    cryptStream.Close();
                    
                    return result;
                }
            }
        }
    }
}
