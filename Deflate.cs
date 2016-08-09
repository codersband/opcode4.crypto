using System.IO;
using System.IO.Compression;
using System.Text;

namespace opcode4.crypto
{
    public static class Deflate
    {
        public static byte[] Compress(string str)
        {
            using (var output = new MemoryStream())
            {
                using (var gzip = new DeflateStream(output, CompressionMode.Compress))
                {
                    using (var writer = new StreamWriter(gzip, Encoding.UTF8))
                    {
                        writer.Write(str);
                    }
                }

                return output.ToArray();
            }
        }

        public static byte[] Compress(byte[] bytes)
        {
            using (var output = new MemoryStream())
            {
                using (var gzip = new DeflateStream(output, CompressionMode.Compress))
                {
                    using (var writer = new StreamWriter(gzip, Encoding.UTF8))
                    {
                        writer.Write(Encoding.UTF8.GetString(bytes));
                    }
                }

                return output.ToArray();
            }
        }




        public static string Decompress(byte[] input)
        {
            using (var inputStream = new MemoryStream(input))
            {
                using (var gzip = new DeflateStream(inputStream, CompressionMode.Decompress))
                {
                    using (var reader = new StreamReader(gzip, Encoding.UTF8))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
        
    }
}
