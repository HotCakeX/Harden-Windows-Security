using System;
using System.Runtime.InteropServices;
using System.Security;

#nullable enable

namespace WDACConfig
{
    public static class SecureStringComparer
    {
        /// <summary>
        /// Safely compares two SecureString objects without decrypting them.
        /// Outputs true if they are equal, or false otherwise.
        /// </summary>
        /// <param name="secureString1">First secure string</param>
        /// <param name="secureString2">Second secure string to compare with the first secure string</param>
        /// <returns>true if the SecureStrings are equal; otherwise, false.</returns>
        public static bool Compare(SecureString secureString1, SecureString secureString2)
        {
            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;

            try
            {
                bstr1 = Marshal.SecureStringToBSTR(secureString1);
                bstr2 = Marshal.SecureStringToBSTR(secureString2);

                int length1 = Marshal.ReadInt32(bstr1, -4);
                int length2 = Marshal.ReadInt32(bstr2, -4);

                if (length1 != length2)
                {
                    return false;
                }

                for (int i = 0; i < length1; ++i)
                {
                    byte b1 = Marshal.ReadByte(bstr1, i);
                    byte b2 = Marshal.ReadByte(bstr2, i);

                    if (b1 != b2)
                    {
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                if (bstr1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr1);
                }
                if (bstr2 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr2);
                }
            }
        }
    }
}
