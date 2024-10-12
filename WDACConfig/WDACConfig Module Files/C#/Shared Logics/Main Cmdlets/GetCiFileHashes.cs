using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

#nullable enable

namespace WDACConfig
{
    public static class CiFileHash
    {
        /// <summary>
        /// Method that outputs all 4 kinds of hashes
        /// </summary>
        /// <param name="filePath">The path to the file that is going to be hashed</param>
        /// <returns>WDACConfig.CodeIntegrityHashes object that contains all 4 kinds of hashes</returns>
        public static CodeIntegrityHashes GetCiFileHashes(string filePath)
        {
            return new CodeIntegrityHashes(
                PageHashCalculator.GetPageHash("SHA1", filePath),
                PageHashCalculator.GetPageHash("SHA256", filePath),
                GetAuthenticodeHash(filePath, "SHA1"),
                GetAuthenticodeHash(filePath, "SHA256")
            );
        }

        private static string? GetAuthenticodeHash(string filePath, string hashAlgorithm)
        {
            // A StringBuilder object to store the hash value as a hexadecimal string
            StringBuilder hashString = new(64);
            IntPtr contextHandle = IntPtr.Zero;
            IntPtr hashValue = IntPtr.Zero;

            try
            {
                using FileStream fileStream = File.OpenRead(filePath);
                // DangerousGetHandle returns the handle to the file stream
                nint fileStreamHandle = fileStream.SafeFileHandle.DangerousGetHandle();

                if (fileStreamHandle == IntPtr.Zero)
                {
                    return null;
                }

                if (!WinTrust.CryptCATAdminAcquireContext2(ref contextHandle, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0))
                {
                    throw new InvalidOperationException($"Could not acquire context for {hashAlgorithm}");
                }

                int hashSize = 0;

                if (!WinTrust.CryptCATAdminCalcHashFromFileHandle3(contextHandle, fileStreamHandle, ref hashSize, IntPtr.Zero, WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
                {
                    throw new InvalidOperationException($"Could not hash {filePath} using {hashAlgorithm}");
                }

                hashValue = Marshal.AllocHGlobal(hashSize);

                if (!WinTrust.CryptCATAdminCalcHashFromFileHandle3(contextHandle, fileStreamHandle, ref hashSize, hashValue, WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
                {
                    throw new InvalidOperationException($"Could not hash {filePath} using {hashAlgorithm}");
                }

                for (int offset = 0; offset < hashSize; offset++)
                {
                    // Marshal.ReadByte returns a byte from the hashValue buffer at the specified offset
                    byte b = Marshal.ReadByte(hashValue, offset);
                    // Append the byte to the hashString as a hexadecimal string
                    _ = hashString.Append(b.ToString("X2", CultureInfo.InvariantCulture));
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
                    _ = WinTrust.CryptCATAdminReleaseContext(contextHandle, 0);
                }
            }

            return hashString.ToString();
        }
    }
}
