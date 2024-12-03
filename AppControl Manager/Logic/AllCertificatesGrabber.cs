using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

#pragma warning disable CA2000

// The following functions and methods use the Windows APIs to grab all of the certificates from a signed file

namespace WDACConfig
{

    // a class to throw a custom exception when the certificate has HashMismatch
    public sealed class HashMismatchInCertificateException(string message, string functionName) : Exception($"{functionName}: {message}")
    {
    }

    // Represents a signed CMS and its certificate chain
    public sealed class AllFileSigners(SignedCms signerCertificate, X509Chain certificateChain)
    {
        public SignedCms Signer { get; } = signerCertificate;
        public X509Chain Chain { get; } = certificateChain;
    }

    public partial class AllCertificatesGrabber
    {
        // Structure defining signer information for cryptographic providers
        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CryptProviderSigner
        {
            private readonly uint cbStruct;   // Size of structure
            private System.Runtime.InteropServices.ComTypes.FILETIME sftVerifyAsOf;   // Verification time
            private readonly uint csCertChain;   // Number of certificates in the chain
            private readonly IntPtr pasCertChain;   // Pointer to certificate chain
            private readonly uint dwSignerType;   // Type of signer
            private readonly IntPtr psSigner;   // Pointer to signer
            private readonly uint dwError;   // Error code
            internal uint csCounterSigners;   // Number of countersigners
            internal IntPtr pasCounterSigners;   // Pointer to countersigners
            public IntPtr pChainContext;   // Pointer to chain context
        }

        // Structure defining provider data for cryptographic operations
        // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CryptProviderData
        {
            private readonly uint cbStruct;   // Size of structure
            private readonly IntPtr pWintrustData;   // Pointer to WinTrustData
            private readonly bool fOpenedFile;   // Flag indicating if file is open
            private readonly IntPtr hWndParent;   // Handle to parent window
            private readonly IntPtr pgActionId;   // Pointer to action ID
            private readonly IntPtr hProv;   // Handle to provider
            private readonly uint dwError;   // Error code
            private readonly uint dwRegSecuritySettings;   // Security settings
            private readonly uint dwRegPolicySettings;   // Policy settings
            private readonly IntPtr psPfns;   // Pointer to provider functions
            private readonly uint cdwTrustStepErrors;   // Number of trust step errors
            private readonly IntPtr padwTrustStepErrors;   // Pointer to trust step errors
            private readonly uint chStores;   // Number of stores
            private readonly IntPtr pahStores;   // Pointer to stores
            private readonly uint dwEncoding;   // Encoding type
            public IntPtr hMsg;   // Handle to message
            public uint csSigners;   // Number of signers
            public IntPtr pasSigners;   // Pointer to signers
        }

        // Structure defining signature settings for WinTrust
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustSignatureSettings
        {
            public uint cbStruct = (uint)Marshal.SizeOf<WinTrustSignatureSettings>();   // Size of structure
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
            private readonly uint StructSize = (uint)Marshal.SizeOf<FileInfoForWinTrust>();   // Size of structure
            private readonly IntPtr FilePath;   // File path pointer
            private readonly IntPtr hFile = IntPtr.Zero;   // File handle pointer
            private readonly IntPtr pgKnownSubject = IntPtr.Zero;   // Pointer to known subject

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
            public uint StructSize = (uint)Marshal.SizeOf<WinTrustData>();   // Size of structure
            public IntPtr PolicyCallbackData = IntPtr.Zero;   // Pointer to policy callback data
            public IntPtr SIPClientData = IntPtr.Zero;   // Pointer to SIP client data
            public uint UIChoice = 2;   // UI choice for trust verification
            public uint RevocationChecks;   // Revocation checks
            public uint UnionChoice = 1;   // Union choice for trust verification
            public IntPtr FileInfoPtr;   // Pointer to file information
            public uint StateAction = WinTrust.StateActionVerify;   // State action for trust verification
            public IntPtr StateData = IntPtr.Zero;   // Pointer to state data
            [MarshalAs(UnmanagedType.LPTStr)]
            private readonly string? URLReference;   // URL reference for trust verification
            public uint ProvFlags = 4112;   // Provider flags for trust verification
            public uint UIContext;   // UI context for trust verification
            public IntPtr pSignatureSettings;   // Pointer to signature settings

            // Constructor initializes with file path and index
            public WinTrustData(string filepath, uint Index)
            {
                // Initialize FileInfoForWinTrust
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<FileInfoForWinTrust>());

                // Initialize pSignatureSettings
                pSignatureSettings = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustSignatureSettings>());

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
        internal static partial class Crypt32DLL
        {
            internal const int EncodedMessageParameter = 29;

            // External method declaration for CryptMsgGetParam
            [LibraryImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            internal static partial bool CryptMsgGetParam(
                IntPtr hCryptMsg,
                int dwParamType,
                int dwIndex,
                [Out] byte[]? pvData, // pvData is populated by CryptMsgGetParam with data from the cryptographic message
                ref int pcbData
            );
        }


        // This is the main method used to retrieve all signers for a given file
        public static List<AllFileSigners> GetAllFileSigners(string FilePath)
        {
            // List to hold all file signers
            List<AllFileSigners> AllFileSigners = [];
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
                    WinTrust.WinVerifyTrustResult verifyTrustResult = WinTrust.WinVerifyTrust(
                        IntPtr.Zero,
                        ref WinTrust.GenericWinTrustVerifyActionGuid,
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
                            WinTrustSignatureSettings? signatureSettings = Marshal.PtrToStructure<WinTrustSignatureSettings>(TrustedData.pSignatureSettings);

                            // Ensuring that the structure is not null before accessing its members
                            if (signatureSettings is not null)
                            {
                                maxSigners = signatureSettings.SecondarySignersCount;
                            }
                        }
                    }

                    // If the certificate is expired, continue to the next iteration
                    if (verifyTrustResult == WinTrust.WinVerifyTrustResult.CertExpired)
                    {
                        continue;
                    }

                    // if there is a hash mismatch in the file, throw an exception
                    if (verifyTrustResult == WinTrust.WinVerifyTrustResult.HashMismatch)
                    {
                        // Throw a custom exception
                        throw new HashMismatchInCertificateException($"WinTrust return code: {verifyTrustResult}", $"The file '{FilePath}' is tampered with and there is a Hash Mismatch.");
                    }

                    // If there is valid state data
                    if (TrustedData.StateData != IntPtr.Zero)
                    {
                        // Get provider data from state data
                        CryptProviderData providerData = Marshal.PtrToStructure<CryptProviderData>(WinTrust.WTHelperProvDataFromStateData(TrustedData.StateData));

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
                                SignedCms signerCertificate = new();
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
                    if (TrustedData is not null)
                    {
                        // Set StateAction to close the WinTrustData structure
                        TrustedData.StateAction = WinTrust.StateActionClose;

                        // Convert TrustedData back to pointer and call WinVerifyTrust to close the structure
                        Marshal.StructureToPtr(TrustedData, winTrustDataPointer, false);
                        _ = WinTrust.WinVerifyTrust(IntPtr.Zero, ref WinTrust.GenericWinTrustVerifyActionGuid, winTrustDataPointer);
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
