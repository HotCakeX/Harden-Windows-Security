using System;
using System.Runtime.InteropServices;

namespace WDACConfig
{
    // This class contains all of the WinTrust related functions and codes
    internal partial class WinTrust
    {
        #region necessary logics for Authenticode and First Page hash calculation

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

        #endregion



        #region This section is related to the MeowParser class operations

        // P/Invoke declaration to import the 'CryptCATOpen' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatopen
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATOpen(
            [MarshalAs(UnmanagedType.LPWStr)] string FileName, // The name of the catalog file.
            uint OpenFlags, // Flags to control the function behavior.
            IntPtr MainCryptProviderHandle, // Handle to the cryptographic service provider.
            uint PublicVersion, // The public version number.
            uint EncodingType); // The encoding type.

        // P/Invoke declaration to import the 'CryptCATEnumerateMember' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatenumeratemember
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATEnumerateMember(
            IntPtr MeowLogHandle, // Handle to the catalog context.
            IntPtr PrevCatalogMember); // Pointer to the previous catalog member.

        // P/Invoke declaration to import the 'CryptCATClose' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatclose
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATClose(IntPtr MainCryptProviderHandle); // Closes the catalog context.

        #endregion



        #region This section is related to the PageHashCalculator class

        // a method to compute the hash of the first page of a file using a native function from Wintrust.dll
        [DllImport("Wintrust.dll", CharSet = CharSet.Unicode)] // an attribute to specify the DLL name and the character set
        internal static extern int ComputeFirstPageHash( // the method signature
            string pszAlgId, // the first parameter: the name of the hash algorithm to use
            string filename, // the second parameter: the name of the file to hash
            IntPtr buffer, // the third parameter: a pointer to a buffer to store the hash value
            int bufferSize // the fourth parameter: the size of the buffer in bytes
        );

        #endregion



        #region This section is related to the AllCertificatesGrabber class and its operations

        // Enum defining WinVerifyTrust results
        public enum WinVerifyTrustResult : uint
        {
            Success = 0, // It's Success
            SubjectCertificateRevoked = 2148204812, // Subject's certificate was revoked. (CERT_E_REVOKED)
            SubjectNotTrusted = 2148204548, // Subject failed the specified verification action
            CertExpired = 2148204801, // This is checked for - Signer's certificate was expired. (CERT_E_EXPIRED)
            UntrustedRootCert = 2148204809, // A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider. (CERT_E_UNTRUSTEDROOT)
            HashMismatch = 2148098064, // This is checked for (aka: SignatureOrFileCorrupt) - (TRUST_E_BAD_DIGEST)
            ProviderUnknown = 2148204545, // Trust provider is not recognized on this system
            ActionUnknown = 2148204546, // Trust provider does not support the specified action
            SubjectFormUnknown = 2148204547, // Trust provider does not support the subject's form
            FileNotSigned = 2148204800, // File is not signed. (TRUST_E_NOSIGNATURE)
            SubjectExplicitlyDistrusted = 2148204817, // Signer's certificate is in the Untrusted Publishers store
        }


        // Constants related to WinTrust
        internal const uint StateActionVerify = 1;
        internal const uint StateActionClose = 2;
        internal static readonly Guid GenericWinTrustVerifyActionGuid = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        // External method declarations for WinVerifyTrust and WTHelperProvDataFromStateData
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]

        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
        // Set to return a WinVerifyTrustResult enum
        internal static extern WinVerifyTrustResult WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            IntPtr pWVTData);

        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

        #endregion

    }
}
