using System;
using System.Security.Cryptography;
using System.Text;
using opcode4.utilities;

namespace opcode4.crypto.RSA
{
    public class RSA : IDisposable
    {
        private readonly RSACryptoServiceProvider _rsa;
        
        public RSA(string key)
        {
            _rsa = new RSACryptoServiceProvider();
            _rsa.FromXmlString(Base64.DecodeBase64URL_ToString(key));
        }

        public string Enrcypt(string data)
        {
            var encar = _rsa.Encrypt(Encoding.UTF8.GetBytes(data), false);
            return Base64.EncodeBase64URL(encar);
        }

        public string Decrypt(string data)
        {
            var decar = Base64.DecodeBase64URL(data);
            
            return Encoding.UTF8.GetString(_rsa.Decrypt(decar, false));
        }

        /// <summary>
        /// Use with public key. Sign with SHA1
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Sign(byte[] data)
        {
            return _rsa.SignData(data, new SHA1CryptoServiceProvider());
        }
        /// <summary>
        /// Use with public key. Sign with SHA1 to base64URL string
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Sign(string data)
        {
            return Base64.EncodeBase64URL(Sign(Encoding.UTF8.GetBytes(data)));
        }

        /// <summary>
        /// Use with private key. Validate with SHA1 hashed signature (and base64URL encoded)
        /// </summary>
        /// <param name="data"></param>
        /// <param name="base64EncodedSignature"></param>
        /// <returns></returns>
        public bool IsValidSignature(string data, string base64EncodedSignature)
        {
            return _rsa.VerifyData(Encoding.UTF8.GetBytes(data), new SHA1CryptoServiceProvider(), Base64.DecodeBase64URL(base64EncodedSignature));
        }

        /// <summary>
        /// Use with private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool IsValidSignature(byte[] data, byte[] signature)
        {
            return _rsa.VerifyData(data, new SHA1CryptoServiceProvider(), signature);
        }

        /// <summary>
        /// Generates public and private keys
        /// <para>a RSA key length of 1024 bits is sufficient for many medium-security purposes such as web site logins</para>
        /// <para>for high-security applications or for data that needs to remain confidential for more than a few years, you should use at least a 2048-bit key</para>
        /// <para>to keep data confidential for more than the next two decades, RSA recommends a key size larger than 2048 bits</para>
        /// </summary>
        /// <param name="keyLength"></param>
        /// <returns>public and private keys as strings</returns>
        public static RsaKeys GenerateKeys(RsaKeyLength keyLength)
        {
            var rsaKey = new RSACryptoServiceProvider((int)keyLength);
            return new RsaKeys
            {
                PublicKey = Base64.EncodeBase64URL(rsaKey.ToXmlString(false)),
                PrivateKey = Base64.EncodeBase64URL(rsaKey.ToXmlString(true))
            };
        }

        /// <summary>
        /// Generates public and private keys
        /// <para>a RSA key length of 1024 bits will be used</para>
        /// <para>The key sufficient for many medium-security purposes such as web site logins</para>
        /// <para>for high-security applications or for data that needs to remain confidential for more than a few years, you should use at least a 2048-bit key</para>
        /// <para>to keep data confidential for more than the next two decades, RSA recommends a key size larger than 2048 bits</para>
        /// </summary>
        /// <returns>public and private keys as strings</returns>
        public static RsaKeys GenerateKeys()
        {
            return GenerateKeys(RsaKeyLength.Key1024);
        }


        public enum RsaKeyLength
        {
            Key384 = 384,
            Key512 = 512,
            Key768 = 768,
            Key800 = 800,
            Key1024 = 1024,
            Key1280 = 1280,
            Key1536 = 1536,
            Key1792 = 1792,
            Key2048 = 2048,
            Key2304 = 2304,
            Key2560 = 2560,
            Key2816 = 2816,
            Key3072 = 3072,
            Key3328 = 3328,
            Key3584 = 3584,
            Key3840 = 3840,
            Key4096 = 4096
        }

        
        public void Dispose()
        {
            _rsa.Dispose();
        }
    }

    public class RsaKeys
    {
        public string PublicKey { set; get; }
        public string PrivateKey { set; get; }
    }
}
