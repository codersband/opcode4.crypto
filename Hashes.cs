using System;
using System.Security.Cryptography;
using System.Text;
using opcode4.utilities;

namespace opcode4.crypto
{
    public static class Hashes
    {
        public static string Sha1(byte[] data)
        {
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                return Convert.ToBase64String(sha1.ComputeHash(data));
            }
            
        }

        public static string Sha1(string data)
        {
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                return Convert.ToBase64String(sha1.ComputeHash(Encoding.Default.GetBytes(data)));
            }

        }

        public static string MD5x2(string source)
        {
            var x = new MD5CryptoServiceProvider();
            var bs = Encoding.UTF8.GetBytes(source);
            bs = x.ComputeHash(bs);
            var sb = new StringBuilder();
            foreach (byte b in bs)
            {
                sb.Append(b.ToString("x2").ToLower());
            }
            return sb.ToString();
        }

        public static string MD5(string s)
        {
            return Base64.EncodeBase64(System.Security.Cryptography.MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(s)));
        }

        public static string HashString(string source)
        {
            var num = source.GetHashCode();

            return num.ToString("x2");

        }

        #region ELF hash functions

        public static long ElfHash(string s)
        {
            var res = 0;

            if (String.IsNullOrEmpty(s))
                return res;

            var s1 = s.ToLower();
            try
            {
                for (var i = 0; i < s1.Length; i++)
                {
                    var b = s1[i];
                    res = (res << 4) + b;
                    var x = res & 0xf000000;
                    if (x != 0) res = res ^ (x >> 24);
                    res = res & (~x);
                }
            }
            catch { }

            return res;
        }

        public static string ElfHashS(string s)
        {
            var r = ElfHash(s);
            return r <= 0 ? "" : r.ToString();
        }

        public static string HashPhone(string phone)
        {
            if (String.IsNullOrEmpty(phone))
                return "";

            const string nums = "0123456789";

            var sb = new StringBuilder();
            for (var i = 0; i < phone.Length; i++)
            {
                if (nums.IndexOf(phone[i]) >= 0)
                    sb.Append(phone[i]);
            }

            return ElfHashS(sb.ToString());
        }

        public static string HashRestrictedLength(string s, int len)
        {
            if (String.IsNullOrEmpty(s))
                return "";

            var r = s.Replace(" ", "").Replace("-", "");
            return ElfHashS(len > 0 && r.Length > len ? r.Substring(0, len) : r);
        }

        public static string HashDateTime(DateTime? dt)
        {
            return dt == null ? "" : ElfHashS(((DateTime)dt).ToString("yyyyMMddHHmm"));
        }

        #endregion ELF hash functions
    }
}
