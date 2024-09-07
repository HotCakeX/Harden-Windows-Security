using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

#nullable enable

namespace WDACConfig
{
    // necessary logics for Authenticode and First Page hash calculation
    internal class WinTrust
    {
        // a constant field that defines a flag value for the native function
        // This causes/helps the GetCiFileHashes method to return the flat file hashes whenever a non-conformant file is encountered
        internal const uint CryptcatadminCalchashFlagNonconformantFilesFallbackFlat = 1;

        // a method to acquire a handle to a catalog administrator context using a native function from WinTrust.dll
        [DllImport("WinTrust.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminAcquireContext2(
            ref IntPtr hCatAdmin, // the first parameter: a reference to a pointer to store the handle
            IntPtr pgSubsystem, // the second parameter: a pointer to a GUID that identifies the subsystem
            string pwszHashAlgorithm, // the third parameter: a string that specifies the hash algorithm to use
            IntPtr pStrongHashPolicy, // the fourth parameter: a pointer to a structure that specifies the strong hash policy
            uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
        );

        // a method to release a handle to a catalog administrator context using a native function from WinTrust.dll
        [DllImport("WinTrust.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminReleaseContext(
            IntPtr hCatAdmin, // the first parameter: a pointer to the handle to release
            uint dwFlags // the second parameter: a flag value that controls the behavior of the function
        );

        // a method to calculate the hash of a file using a native function from WinTrust.dll
        [DllImport("WinTrust.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminCalcHashFromFileHandle3(
            IntPtr hCatAdmin, // the first parameter: a pointer to the handle of the catalog administrator context
            IntPtr hFile, // the second parameter: a pointer to the handle of the file to hash
            ref int pcbHash, // the third parameter: a reference to an integer that specifies the size of the hash buffer
            IntPtr pbHash, // the fourth parameter: a pointer to a buffer to store the hash value
            uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
        );
    }

    public static class AuthPageHash
    {
        /// <summary>
        /// Method that outputs all 4 kinds of hashes
        /// </summary>
        /// <param name="filePath">The path to the file that is going to be hashed</param>
        /// <returns>WDACConfig.AuthenticodePageHashes object that contains all 4 kinds of hashes</returns>
        public static WDACConfig.AuthenticodePageHashes GetCiFileHashes(string filePath)
        {
            return new WDACConfig.AuthenticodePageHashes(
                WDACConfig.PageHashCalculator.GetPageHash("SHA1", filePath),
                WDACConfig.PageHashCalculator.GetPageHash("SHA256", filePath),
                GetAuthenticodeHash(filePath, "SHA1"),
                GetAuthenticodeHash(filePath, "SHA256")
            );
        }

        private static string? GetAuthenticodeHash(string filePath, string hashAlgorithm)
        {
            // A StringBuilder object to store the hash value as a hexadecimal string
            StringBuilder hashString = new StringBuilder(64);
            IntPtr contextHandle = IntPtr.Zero;
            IntPtr fileStreamHandle = IntPtr.Zero;
            IntPtr hashValue = IntPtr.Zero;

            try
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    // DangerousGetHandle returns the handle to the file stream
                    fileStreamHandle = fileStream.SafeFileHandle.DangerousGetHandle();

                    if (fileStreamHandle == IntPtr.Zero)
                    {
                        return null;
                    }

                    if (!WDACConfig.WinTrust.CryptCATAdminAcquireContext2(ref contextHandle, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0))
                    {
                        throw new Exception($"Could not acquire context for {hashAlgorithm}");
                    }

                    int hashSize = 0;

                    if (!WDACConfig.WinTrust.CryptCATAdminCalcHashFromFileHandle3(contextHandle, fileStreamHandle, ref hashSize, IntPtr.Zero, WDACConfig.WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
                    {
                        throw new Exception($"Could not hash {filePath} using {hashAlgorithm}");
                    }

                    hashValue = Marshal.AllocHGlobal(hashSize);

                    if (!WDACConfig.WinTrust.CryptCATAdminCalcHashFromFileHandle3(contextHandle, fileStreamHandle, ref hashSize, hashValue, WDACConfig.WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
                    {
                        throw new Exception($"Could not hash {filePath} using {hashAlgorithm}");
                    }

                    for (int offset = 0; offset < hashSize; offset++)
                    {
                        // Marshal.ReadByte returns a byte from the hashValue buffer at the specified offset
                        byte b = Marshal.ReadByte(hashValue, offset);
                        // Append the byte to the hashString as a hexadecimal string
                        hashString.Append(b.ToString("X2", CultureInfo.InvariantCulture));
                    }
                }
            }
            finally
            {
                if (hashValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(hashValue);
                }

                if (contextHandle != IntPtr.Zero)
                {
                    WDACConfig.WinTrust.CryptCATAdminReleaseContext(contextHandle, 0);
                }
            }

            return hashString.ToString();
        }
    }
}
