using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

#nullable enable

// The following functions and methods use the Windows APIs to grab all of the certificates from a signed file

namespace WDACConfig.AllCertificatesGrabber
{

    // a class to throw a custom exception when the certificate has HashMismatch
    public class ExceptionHashMismatchInCertificate : Exception
    {
        public ExceptionHashMismatchInCertificate(string message, string functionName)
            : base($"{functionName}: {message}")
        {
        }
    }

    // Represents a signed CMS and its certificate chain
    public class AllFileSigners
    {
        public SignedCms Signer { get; }   // SignedCms object containing signer's certificate and message
        public X509Chain Chain { get; }    // X509Chain object representing the certificate chain

        // Constructor initializes with signer certificate and certificate chain
        public AllFileSigners(SignedCms signerCertificate, X509Chain certificateChain)
        {
            Signer = signerCertificate;
            Chain = certificateChain;
        }
    }

    // Interop with wintrust.dll for Windows Trust Verification
    public static class WinTrust
    {
        // Structure defining signer information for cryptographic providers
        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CryptProviderSigner
        {
            private uint cbStruct;   // Size of structure
            private System.Runtime.InteropServices.ComTypes.FILETIME sftVerifyAsOf;   // Verification time
            private uint csCertChain;   // Number of certificates in the chain
            private IntPtr pasCertChain;   // Pointer to certificate chain
            private uint dwSignerType;   // Type of signer
            private IntPtr psSigner;   // Pointer to signer
            private uint dwError;   // Error code
            internal uint csCounterSigners;   // Number of countersigners
            internal IntPtr pasCounterSigners;   // Pointer to countersigners
            public IntPtr pChainContext;   // Pointer to chain context
        }

        // Structure defining provider data for cryptographic operations
        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CryptProviderData
        {
            private uint cbStruct;   // Size of structure
            private IntPtr pWintrustData;   // Pointer to WinTrustData
            private bool fOpenedFile;   // Flag indicating if file is open
            private IntPtr hWndParent;   // Handle to parent window
            private IntPtr pgActionId;   // Pointer to action ID
            private IntPtr hProv;   // Handle to provider
            private uint dwError;   // Error code
            private uint dwRegSecuritySettings;   // Security settings
            private uint dwRegPolicySettings;   // Policy settings
            private IntPtr psPfns;   // Pointer to provider functions
            private uint cdwTrustStepErrors;   // Number of trust step errors
            private IntPtr padwTrustStepErrors;   // Pointer to trust step errors
            private uint chStores;   // Number of stores
            private IntPtr pahStores;   // Pointer to stores
            private uint dwEncoding;   // Encoding type
            public IntPtr hMsg;   // Handle to message
            public uint csSigners;   // Number of signers
            public IntPtr pasSigners;   // Pointer to signers
        }

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

        // Structure defining signature settings for WinTrust
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustSignatureSettings
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustSignatureSettings));   // Size of structure
            public uint dwIndex;   // Index of the signature
            public uint dwFlags = 3;   // Flags for signature verification
            public uint SecondarySignersCount;   // Number of secondary signatures
            public uint dwVerifiedSigIndex;   // Index of verified signature
            public IntPtr pCryptoPolicy = IntPtr.Zero;   // Pointer to cryptographic policy

            // Default constructor initializes dwIndex to unsigned integer 0
            public WinTrustSignatureSettings()
            {
                dwIndex = 0U;
            }

            // Constructor initializes with given index
            public WinTrustSignatureSettings(uint index)
            {
                dwIndex = index;
            }
        }

        // Structure defining file information for WinTrust
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class FileInfoForWinTrust
        {
            private uint StructSize = (uint)Marshal.SizeOf(typeof(FileInfoForWinTrust));   // Size of structure
            private IntPtr FilePath;   // File path pointer
            private IntPtr hFile = IntPtr.Zero;   // File handle pointer
            private IntPtr pgKnownSubject = IntPtr.Zero;   // Pointer to known subject

            // Default constructor initializes FilePath to null
            public FileInfoForWinTrust()
            {
                FilePath = IntPtr.Zero;
            }

            // Constructor initializes FilePath with the given filePath
            public FileInfoForWinTrust(string filePath)
            {
                FilePath = Marshal.StringToCoTaskMemAuto(filePath);
            }

            // Destructor frees allocated memory for FilePath
            ~FileInfoForWinTrust()
            {
                Marshal.FreeCoTaskMem(FilePath);
            }
        }

        // Structure defining overall trust data for WinTrust
        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustData
        {
            public uint StructSize = (uint)Marshal.SizeOf(typeof(WinTrustData));   // Size of structure
            public IntPtr PolicyCallbackData = IntPtr.Zero;   // Pointer to policy callback data
            public IntPtr SIPClientData = IntPtr.Zero;   // Pointer to SIP client data
            public uint UIChoice = 2;   // UI choice for trust verification
            public uint RevocationChecks;   // Revocation checks
            public uint UnionChoice = 1;   // Union choice for trust verification
            public IntPtr FileInfoPtr;   // Pointer to file information
            public uint StateAction = StateActionVerify;   // State action for trust verification
            public IntPtr StateData = IntPtr.Zero;   // Pointer to state data
            [MarshalAs(UnmanagedType.LPTStr)]
            private string? URLReference;   // URL reference for trust verification
            public uint ProvFlags = 4112;   // Provider flags for trust verification
            public uint UIContext;   // UI context for trust verification
            public IntPtr pSignatureSettings;   // Pointer to signature settings

            // Constructor initializes with file path and index
            public WinTrustData(string filepath, uint Index)
            {
                // Initialize FileInfoForWinTrust
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(FileInfoForWinTrust)));

                // Initialize pSignatureSettings
                pSignatureSettings = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustSignatureSettings)));

                // Convert TrustedData to pointer and assign to FileInfoPtr
                Marshal.StructureToPtr(new FileInfoForWinTrust(filepath), FileInfoPtr, false);

                // Convert providerData to pointer and assign to pSignatureSettings
                Marshal.StructureToPtr(new WinTrustSignatureSettings(Index), pSignatureSettings, false);
            }

            // Destructor frees allocated memory for FileInfoPtr and pSignatureSettings
            ~WinTrustData()
            {
                Marshal.FreeCoTaskMem(FileInfoPtr);   // Free memory allocated to FileInfoPtr
                Marshal.FreeCoTaskMem(pSignatureSettings);   // Free memory allocated to pSignatureSettings
            }
        }

        // Interop with crypt32.dll for cryptographic functions
        internal static class Crypt32DLL
        {
            internal const int EncodedMessageParameter = 29;

            // External method declaration for CryptMsgGetParam
            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            internal static extern bool CryptMsgGetParam(
                IntPtr hCryptMsg,
                int dwParamType,
                int dwIndex,
                byte[]? pvData,
                ref int pcbData
                );
        }

        // Constants related to WinTrust
        internal const uint StateActionVerify = 1;
        internal const uint StateActionClose = 2;
        internal static readonly Guid GenericWinTrustVerifyActionGuid = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

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

        // This is the main method used to retrieve all signers for a given file
        public static List<AllFileSigners> GetAllFileSigners(string FilePath)
        {
            // List to hold all file signers
            List<AllFileSigners> AllFileSigners = new List<AllFileSigners>();
            uint maxSigners = uint.MaxValue;   // Maximum number of signers to process, initially set to maximum possible value
            uint Index = 0;   // Index of the current signer being processed

            do
            {
                WinTrustData? TrustedData = null;   // Declare a WinTrustData structure variable
                IntPtr winTrustDataPointer = IntPtr.Zero;   // Pointer to WinTrustData structure

                try
                {
                    // Initialize WinTrustData structure for file at FilePath and given index
                    TrustedData = new WinTrustData(FilePath, Index);

                    // Allocate memory for WinTrustData structure and convert TrustedData to a pointer
                    winTrustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf(TrustedData));
                    Marshal.StructureToPtr(TrustedData, winTrustDataPointer, false);

                    // Call WinVerifyTrust to verify trust on the file
                    WinVerifyTrustResult verifyTrustResult = WinVerifyTrust(
                        IntPtr.Zero,
                        GenericWinTrustVerifyActionGuid,
                        winTrustDataPointer
                    );

                    // Update TrustedData with data from the pointer
                    Marshal.PtrToStructure(winTrustDataPointer, TrustedData);

                    // Check signature settings and process the signer's certificate
                    if (maxSigners == uint.MaxValue)
                    {
                        // First, checking if TrustedData.pSignatureSettings is not IntPtr.Zero (which means it is not null)
                        if (TrustedData.pSignatureSettings != IntPtr.Zero)
                        {
                            // Using the generic overload of Marshal.PtrToStructure for better type safety and performance
                            var signatureSettings = Marshal.PtrToStructure<WinTrustSignatureSettings>(TrustedData.pSignatureSettings);

                            // Ensuring that the structure is not null before accessing its members
                            if (signatureSettings != null)
                            {
                                maxSigners = signatureSettings.SecondarySignersCount;
                            }
                        }
                    }

                    // If the certificate is expired, continue to the next iteration
                    if (verifyTrustResult == WinVerifyTrustResult.CertExpired)
                    {
                        continue;
                    }

                    // if there is a hash mismatch in the file, throw an exception
                    if (verifyTrustResult == WinVerifyTrustResult.HashMismatch)
                    {
                        // Throw a custom exception that will be caught by Invoke-WDACPolicySimulation cmdlet
                        throw new ExceptionHashMismatchInCertificate($"WinTrust return code: {verifyTrustResult}", "The file is tampered with and there is a Hash Mismatch.");
                    }

                    // If there is valid state data
                    if (TrustedData.StateData != IntPtr.Zero)
                    {
                        // Get provider data from state data
                        CryptProviderData providerData = Marshal.PtrToStructure<CryptProviderData>(WTHelperProvDataFromStateData(TrustedData.StateData));

                        int pcbData = 0;   // Size of data in bytes

                        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
                        // Get size of encoded message
                        if (providerData.hMsg != IntPtr.Zero && Crypt32DLL.CryptMsgGetParam(
                            providerData.hMsg,          // Handle to the cryptographic message
                            Crypt32DLL.EncodedMessageParameter, // Parameter type to retrieve (encoded message)
                            0,                          // Index of the parameter to retrieve
                            null,                       // Pointer to the buffer that receives the data (null to get the size)
                            ref pcbData                 // Size of the data in bytes (output parameter)
                            )
                            )
                        {
                            // Array to hold encoded message data
                            byte[] numArray = new byte[pcbData];

                            // Retrieve the encoded message and decode it
                            if (Crypt32DLL.CryptMsgGetParam(
                                    providerData.hMsg, // Handle to the cryptographic message
                                    Crypt32DLL.EncodedMessageParameter, // Parameter type to retrieve (encoded message)
                                    0, // Index of the parameter to retrieve
                                    numArray, // Pointer to the buffer that receives the data
                                    ref pcbData // Size of the data in bytes (output parameter)
                                )
                            )
                            {
                                // Initialize SignedCms object and decode the encoded message
                                SignedCms signerCertificate = new SignedCms();
                                signerCertificate.Decode(numArray);

                                // Initialize X509Chain object based on signer's certificate chain context
                                X509Chain certificateChain;

                                // Check if csSigners is less than or equal to 0
                                if (providerData.csSigners <= 0U)
                                {
                                    // If csSigners is 0 or negative, create a new X509Chain without parameters
                                    certificateChain = new X509Chain();
                                }
                                else
                                {
                                    // Otherwise, get the CryptProviderSigner structure from pasSigners pointer
                                    // Using the generic overload to marshal the structure for better performance and type safety
                                    CryptProviderSigner signer = Marshal.PtrToStructure<CryptProviderSigner>(providerData.pasSigners);

                                    // Initialize X509Chain with the pChainContext from the signer structure
                                    certificateChain = new X509Chain(signer.pChainContext);
                                }

                                // Add signer's certificate and certificate chain to AllFileSigners list
                                AllFileSigners.Add(new AllFileSigners(signerCertificate, certificateChain));
                            }
                        }
                    }
                }
                finally
                {
                    if (TrustedData != null)
                    {
                        // Set StateAction to close the WinTrustData structure
                        TrustedData.StateAction = StateActionClose;

                        // Convert TrustedData back to pointer and call WinVerifyTrust to close the structure
                        Marshal.StructureToPtr(TrustedData, winTrustDataPointer, false);
                        WinVerifyTrust(IntPtr.Zero, GenericWinTrustVerifyActionGuid, winTrustDataPointer);
                    }

                    // Free memory allocated to winTrustDataPointer
                    Marshal.FreeHGlobal(winTrustDataPointer);

                    // Increment Index for the next signer
                    Index++;
                }
            } while (Index < maxSigners + 1U);   // Continue loop until all signers are processed

            return AllFileSigners;   // Return list of all file signers
        }
    }
}
