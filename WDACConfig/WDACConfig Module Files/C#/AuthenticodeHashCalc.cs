// necessary logics for Authenticode hash calculation
using System;
using System.Runtime.InteropServices; // for interoperability with unmanaged code
using System.Text;
using System.IO;

namespace WDACConfig
{
    public class WinTrust // a public class that can be accessed from anywhere
    {
        public const uint CryptcatadminCalchashFlagNonconformantFilesFallbackFlat = 1; // a public constant field that defines a flag value for the native function
        // This causes/helps the Get-CiFileHashes function to return the flat file hashes whenever a non-conformant file is encountered

        // a method to acquire a handle to a catalog administrator context using a native function from Wintrust.dll
        [DllImport("Wintrust.dll", CharSet = CharSet.Unicode)] // an attribute to specify the DLL name and the character set
        public static extern bool CryptCATAdminAcquireContext2( // the method signature
            ref IntPtr hCatAdmin, // the first parameter: a reference to a pointer to store the handle
            IntPtr pgSubsystem, // the second parameter: a pointer to a GUID that identifies the subsystem
            string pwszHashAlgorithm, // the third parameter: a string that specifies the hash algorithm to use
            IntPtr pStrongHashPolicy, // the fourth parameter: a pointer to a structure that specifies the strong hash policy
            uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
        );

        // a method to release a handle to a catalog administrator context using a native function from Wintrust.dll
        [DllImport("Wintrust.dll", CharSet = CharSet.Unicode)] // an attribute to specify the DLL name and the character set
        public static extern bool CryptCATAdminReleaseContext( // the method signature
            IntPtr hCatAdmin, // the first parameter: a pointer to the handle to release
            uint dwFlags // the second parameter: a flag value that controls the behavior of the function
        );

        // a method to calculate the hash of a file using a native function from Wintrust.dll
        [DllImport("Wintrust.dll", CharSet = CharSet.Unicode)] // an attribute to specify the DLL name and the character set
        public static extern bool CryptCATAdminCalcHashFromFileHandle3( // the method signature
            IntPtr hCatAdmin, // the first parameter: a pointer to the handle of the catalog administrator context
            IntPtr hFile, // the second parameter: a pointer to the handle of the file to hash
            ref int pcbHash, // the third parameter: a reference to an integer that specifies the size of the hash buffer
            IntPtr pbHash, // the fourth parameter: a pointer to a buffer to store the hash value
            uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
        );
    }
}
