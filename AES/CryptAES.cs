using System;
using System.Security.Cryptography;
using System.Text;
using opcode4.utilities;

namespace opcode4.crypto.AES
{
    public class CryptAES
    {
        private CipherKey _key;
        private RijndaelManaged InitCipher()
        {
            _key = CipherKey.GetCipherKey(EncLevel);
            return new RijndaelManaged
                        {
                            Mode = AesMode,
                            Padding = AesPadding,
                            KeySize = _key.Size,
                            BlockSize = _key.Size
                        }; 
        }
        
        public CipherMode AesMode = CipherMode.CBC;
        public PaddingMode AesPadding = PaddingMode.PKCS7;
        public EncriptionLevel EncLevel = EncriptionLevel.Medium;

        public CryptAES(){}
        public CryptAES(CipherMode cm, PaddingMode pm, EncriptionLevel el)
        {
            AesMode = cm;
            AesPadding = pm;
            EncLevel = el;
        }

        public byte[] Encrypt(byte[] data, string password)
        {
            var rijndaelCipher = InitCipher();

            var pwdBytes = Encoding.UTF8.GetBytes(password);
            var keyBytes = new byte[_key.Len];
            var len = pwdBytes.Length;
            if (len > keyBytes.Length)
                len = keyBytes.Length;

            Array.Copy(pwdBytes, keyBytes, len);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = keyBytes;
            var transform = rijndaelCipher.CreateEncryptor();

            return transform.TransformFinalBlock(data, 0, data.Length);
        }
        
        public string EncryptString(string text, string password)
        {
            return Base64.EncodeBase64URL(Encrypt(Encoding.UTF8.GetBytes(text), password));
        }

        public byte[] Decrypt(byte[] data, string password)
        {
            var rijndaelCipher = InitCipher();

            var pwdBytes = Encoding.UTF8.GetBytes(password);
            var keyBytes = new byte[_key.Len];
            var len = pwdBytes.Length;
            if (len > keyBytes.Length)
                len = keyBytes.Length;
            Array.Copy(pwdBytes, keyBytes, len);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = keyBytes;
            var transform = rijndaelCipher.CreateDecryptor();

            return transform.TransformFinalBlock(data, 0, data.Length);
        }

        public string DecryptString(string text, string password)
        {
            return Encoding.UTF8.GetString(Decrypt(Base64.DecodeBase64URL(text), password));
        }
    }
}
