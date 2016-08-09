using System;

namespace opcode4.crypto.AES
{
    public enum EncriptionLevel
    {
        Low = 0,
        Medium = 1,
        High = 2,
        Custom = 3
    }

    struct CipherKey
    {
        //const for key length
        private const int LowKeyLen = 16;
        private const int MedKeyLen = 24;
        private const int HigKeyLen = 32;
        //const for block size
        private const int LowKeySiz = 128;
        private const int MedKeySiz = 192;
        private const int HigKeySiz = 256;
        public int Len;
        public int Size;
        //function gets the cipher pair index and return the pair -blocj size ,key length
        public static CipherKey GetCipherKey(EncriptionLevel EncLevel)
        {
            CipherKey Key;
            switch (EncLevel)
            {
                case EncriptionLevel.Custom:
                    {
                        Key.Len = 16;
                        Key.Size = 16;
                        return Key;
                    }
                case EncriptionLevel.Low:
                    {
                        Key.Len = LowKeyLen;
                        Key.Size = LowKeySiz;
                        return Key;
                    }
                case EncriptionLevel.Medium:
                    {
                        Key.Len = MedKeyLen;
                        Key.Size = MedKeySiz;
                        return Key;
                    }
                case EncriptionLevel.High:
                    {
                        Key.Len = HigKeyLen;
                        Key.Size = HigKeySiz;
                        return Key;
                    }
            }
            throw new Exception("Invalid cipher Level- allow 0..2 -get: " + EncLevel.ToString());
        }

    }
}