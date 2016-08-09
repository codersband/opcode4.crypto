using System;
using System.Text;
using opcode4.utilities;

namespace opcode4.crypto.RC4
{
    public class RC4
    {

        private int x;
        private int y;
        private byte[] state = new byte[256];
        private byte[] userKey;


        public RC4(string key)
        {
            userKey = Encoding.UTF8.GetBytes(key);
        }

        public void SetKey(byte[] key)
        {
            userKey = key;
        }

        private byte ArcfourByte()
        {
            x = (x + 1) & 0xff;
            y = (state[x] + y) & 0xff;

            byte swap = state[x];
            state[x] = state[y];
            state[y] = swap;
            return state[((state[x] + state[y]) & 0xff)];
        }

        /**
         * encryption/decryption.
         *
         * @param in        the input data.
         * @param inOffset  the offset into in specifying where the data starts.
         * @param len       the length of the subarray.
         * @param out       the output array.
         * @param outOffset the offset indicating where to start writing into
         *                  the out array.
         * @throws Exception if key not valid.
         */

        public void Crypt(byte[] inbound, int inOffset, int len, byte[] outbound, int outOffset)
        {
            int end = inOffset + len;
            MakeKey(userKey);
            for (int si = inOffset, di = outOffset; si < end; si++, di++)
                outbound[di] = (byte)(((int)inbound[si] ^ ArcfourByte()) & 0xff);
        }

        /**
         * encryption/decryption.
         *
         * @param in       the input data.
         * @param inOffset the offset into in specifying where the data starts.
         * @param len      the length of the subarray.
         * @return out crypted byte array
         * @throws Exception if key not valid.
         */
        public byte[] Crypt(byte[] inbound, int inOffset, int len)
        {
            var outbound = new byte[len];
            Crypt(inbound, inOffset, len, outbound, 0);
            return outbound;
        }

        /**
         * encryption/decryption.
         *
         * @param in the input data.
         * @return out crypted byte array
         * @throws Exception if key not valid.
         */
        public byte[] Crypt(byte[] inbound)
        {
            var outbound = new byte[inbound.Length];
            Crypt(inbound, 0, inbound.Length, outbound, 0);
            return outbound;
        }

        public string CryptBase64(string inbound, Encoding encoding)
        {
            var bytes = encoding.GetBytes(inbound);
            var outbound = new byte[bytes.Length];
            Crypt(bytes, 0, bytes.Length, outbound, 0);
            return Base64.EncodeBase64URL(outbound);
        }

        public string DeCryptBase64(string inbound, Encoding encoding)
        {
            var bytes = Base64.DecodeBase64URL(inbound);
            var outbound = new byte[bytes.Length];
            Crypt(bytes, 0, bytes.Length, outbound, 0);
            return encoding.GetString(outbound);
        }

        public string CryptBase64(string inbound)
        {
            return CryptBase64(inbound, Encoding.UTF8);
        }

        public string DeCryptBase64(string inbound)
        {
            return DeCryptBase64(inbound, Encoding.UTF8);
        }


        public string CryptBase64Deflate(string inbound)
        {
            var bytes = Encoding.UTF8.GetBytes(inbound);
            bytes = Deflate.Compress(bytes);
            
            var outbound = new byte[bytes.Length];
            Crypt(bytes, 0, bytes.Length, outbound, 0);
            
            return Base64.EncodeBase64URL(outbound);
        }

        public string DeCryptBase64Deflate(string inbound)
        {
            var bytes = Base64.DecodeBase64URL(inbound);
            var outbound = new byte[bytes.Length];
            Crypt(bytes, 0, bytes.Length, outbound, 0);

            return Deflate.Decompress(outbound);
        }

        
        private void MakeKey(byte[] key)
        {
            if (key == null || key.Length <= 0)
                throw new Exception("RC4: User key is null or empty.");

            int len = key.Length;
            x = y = 0;
            for (int i = 0; i < 256; i++)
                state[i] = (byte)i;

            int i1 = 0, i2 = 0;

            for (int i = 0; i < 256; i++)
            {
                i2 = ((key[i1] & 0xFF) + state[i] + i2) & 0xFF;

                byte t = state[i];
                state[i] = state[i2];
                state[i2] = t;

                i1 = (i1 + 1) % len;
            }
        }
    }
}
