// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;

namespace AppControlManager.Others;

/// <summary>
/// The following functions and methods use the Windows APIs to grab all of the certificates from a signed file
/// </summary>
internal static class AllCertificatesGrabber
{
	// Constants related to WinTrust
	private const uint StateActionVerify = 1;
	private const uint StateActionClose = 2;
	private static Guid GenericWinTrustVerifyActionGuid = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

	// Structure defining signer information for cryptographic providers
	// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
	[StructLayout(LayoutKind.Sequential)]
	internal struct CryptProviderSigner
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
		internal IntPtr pChainContext;   // Pointer to chain context
	}

	// Structure defining provider data for cryptographic operations
	// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
	[StructLayout(LayoutKind.Sequential)]
	internal struct CryptProviderData
	{
		private readonly uint cbStruct;   // Size of structure
		private readonly IntPtr pWintrustData;   // Pointer to WinTrustData
		private readonly int fOpenedFile;   // Flag indicating if file is open (BOOL -> int for blittability)
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
		internal IntPtr hMsg;   // Handle to message
		internal uint csSigners;   // Number of signers
		internal IntPtr pasSigners;   // Pointer to signers
	}

	// Structure defining signature settings for WinTrust
	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct WinTrustSignatureSettings
	{
		internal uint cbStruct;   // Size of structure
		internal uint dwIndex;   // Index of the signature
		internal uint dwFlags;   // Flags for signature verification
		internal uint SecondarySignersCount;   // Number of secondary signatures
		internal uint dwVerifiedSigIndex;   // Index of verified signature
		internal IntPtr pCryptoPolicy;   // Pointer to cryptographic policy

		// Default constructor initializes dwIndex to unsigned integer 0
		public WinTrustSignatureSettings()
		{
			cbStruct = (uint)sizeof(WinTrustSignatureSettings);
			dwIndex = 0U;
			dwFlags = 3;
			SecondarySignersCount = 0;
			dwVerifiedSigIndex = 0;
			pCryptoPolicy = IntPtr.Zero;
		}

		// Constructor initializes with given index
		internal WinTrustSignatureSettings(uint index)
		{
			cbStruct = (uint)sizeof(WinTrustSignatureSettings);
			dwIndex = index;
			dwFlags = 3;
			SecondarySignersCount = 0;
			dwVerifiedSigIndex = 0;
			pCryptoPolicy = IntPtr.Zero;
		}
	}

	// Structure defining file information for WinTrust
	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct FileInfoForWinTrust
	{
		internal uint StructSize;   // Size of structure
		internal IntPtr FilePath;   // File path pointer (LPCWSTR)
		internal IntPtr hFile;   // File handle pointer
		internal IntPtr pgKnownSubject;   // Pointer to known subject

		// Default constructor initializes FilePath to null
		public FileInfoForWinTrust()
		{
			StructSize = (uint)sizeof(FileInfoForWinTrust);
			FilePath = IntPtr.Zero;
			hFile = IntPtr.Zero;
			pgKnownSubject = IntPtr.Zero;
		}

		// Constructor initializes FilePath with the given filePath
		internal FileInfoForWinTrust(IntPtr filePathPtr)
		{
			StructSize = (uint)sizeof(FileInfoForWinTrust);
			FilePath = filePathPtr;
			hFile = IntPtr.Zero;
			pgKnownSubject = IntPtr.Zero;
		}
	}

	// Structure defining overall trust data for WinTrust
	// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct WinTrustData
	{
		internal uint StructSize;   // Size of structure
		internal IntPtr PolicyCallbackData;   // Pointer to policy callback data
		internal IntPtr SIPClientData;   // Pointer to SIP client data
		internal uint UIChoice;   // UI choice for trust verification
		internal uint RevocationChecks;   // Revocation checks
		internal uint UnionChoice;   // Union choice for trust verification
		internal IntPtr FileInfoPtr;   // Pointer to file information
		internal uint StateAction;   // State action for trust verification
		internal IntPtr StateData;   // Pointer to state data
		internal IntPtr URLReference;   // URL reference for trust verification
		internal uint ProvFlags;   // Provider flags for trust verification
		internal uint UIContext;   // UI context for trust verification
		internal IntPtr pSignatureSettings;   // Pointer to signature settings

		internal WinTrustData(IntPtr fileInfoPtr, IntPtr signatureSettingsPtr)
		{
			StructSize = (uint)sizeof(WinTrustData);
			PolicyCallbackData = IntPtr.Zero;
			SIPClientData = IntPtr.Zero;
			UIChoice = 2;
			RevocationChecks = 0;
			UnionChoice = 1;
			FileInfoPtr = fileInfoPtr;
			StateAction = StateActionVerify;
			StateData = IntPtr.Zero;
			URLReference = IntPtr.Zero;
			ProvFlags = 4112;
			UIContext = 0;
			pSignatureSettings = signatureSettingsPtr;
		}
	}

	// This is the main method used to retrieve all signers for a given file
	internal static unsafe List<AllFileSigners> GetAllFileSigners(string FilePath)
	{
		const int EncodedMessageParameter = 29;

		// List to hold all file signers
		List<AllFileSigners> AllFileSigners = [];
		uint maxSigners = uint.MaxValue;   // Maximum number of signers to process, initially set to maximum possible value
		uint Index = 0;   // Index of the current signer being processed

		do
		{
			IntPtr winTrustDataPointer = IntPtr.Zero;   // Pointer to WinTrustData structure (unmanaged)
			IntPtr fileInfoPtr = IntPtr.Zero;           // Pointer to FileInfoForWinTrust
			IntPtr sigSettingsPtr = IntPtr.Zero;        // Pointer to WinTrustSignatureSettings
			IntPtr filePathPtr = IntPtr.Zero;           // Pointer to unmanaged file path string (LPCWSTR)

			try
			{
				// Allocate unmanaged Unicode string for file path
				filePathPtr = Marshal.StringToHGlobalUni(FilePath);

				// Build FileInfoForWinTrust in unmanaged memory
				fileInfoPtr = Marshal.AllocHGlobal(sizeof(FileInfoForWinTrust));
				FileInfoForWinTrust fileInfo = new(filePathPtr);
				*(FileInfoForWinTrust*)fileInfoPtr = fileInfo;

				// Build WinTrustSignatureSettings (per-signer index) in unmanaged memory
				sigSettingsPtr = Marshal.AllocHGlobal(sizeof(WinTrustSignatureSettings));
				WinTrustSignatureSettings sigSettings = (Index == 0)
					? new WinTrustSignatureSettings()
					: new WinTrustSignatureSettings(Index);
				*(WinTrustSignatureSettings*)sigSettingsPtr = sigSettings;

				// Allocate and initialize WinTrustData
				winTrustDataPointer = Marshal.AllocHGlobal(sizeof(WinTrustData));
				WinTrustData wtd = new(fileInfoPtr, sigSettingsPtr);
				*(WinTrustData*)winTrustDataPointer = wtd;

				// Call WinVerifyTrust to verify trust on the file
				WinVerifyTrustResult verifyTrustResult = NativeMethods.WinVerifyTrust(
					IntPtr.Zero,
					ref GenericWinTrustVerifyActionGuid,
					winTrustDataPointer
				);

				// Reload updated data from unmanaged memory
				wtd = *(WinTrustData*)winTrustDataPointer;

				// Check signature settings and process the signer's certificate
				if (maxSigners == uint.MaxValue)
				{
					if (wtd.pSignatureSettings != IntPtr.Zero)
					{
						WinTrustSignatureSettings* signatureSettings = (WinTrustSignatureSettings*)wtd.pSignatureSettings;
						if (signatureSettings != null)
						{
							// Reading SecondarySignersCount directly from unmanaged struct
							maxSigners = signatureSettings->SecondarySignersCount;
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
					// Throw a custom exception
					throw new HashMismatchInCertificateException(
						string.Format(GlobalVars.GetStr("WinTrustReturnCodeMessage"), verifyTrustResult),
						string.Format(GlobalVars.GetStr("FileTamperedHashMismatchMessage"), FilePath)
					);
				}

				// If there is valid state data
				if (wtd.StateData != IntPtr.Zero)
				{
					// Get provider data from state data
					IntPtr providerDataBase = NativeMethods.WTHelperProvDataFromStateData(wtd.StateData);
					if (providerDataBase != IntPtr.Zero)
					{
						CryptProviderData providerData = *(CryptProviderData*)providerDataBase;

						int pcbData = 0;   // Size of data in bytes

						// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
						// Get size of encoded message
						if (providerData.hMsg != IntPtr.Zero && NativeMethods.CryptMsgGetParam(
								providerData.hMsg,          // Handle to the cryptographic message
								EncodedMessageParameter,    // Parameter type to retrieve (encoded message)
								0,                          // Index of the parameter to retrieve
								null,                       // Pointer to the buffer that receives the data (null to get the size)
								ref pcbData                 // Size of the data in bytes (output parameter)
							)
						   )
						{
							// Array to hold encoded message data
							byte[] numArray = new byte[pcbData];

							// Retrieve the encoded message and decode it
							if (NativeMethods.CryptMsgGetParam(
									providerData.hMsg,              // Handle to the cryptographic message
									EncodedMessageParameter,        // Parameter type to retrieve (encoded message)
									0,                              // Index of the parameter to retrieve
									numArray,                       // Pointer to the buffer that receives the data
									ref pcbData                     // Size of the data in bytes (output parameter)
								)
							   )
							{
								// Initialize SignedCms object and decode the encoded message
								SignedCms signerCertificate = new();
								signerCertificate.Decode(numArray);

								// Check if csSigners is less than or equal to 0
								// Decide how to construct AllFileSigners based on availability of signer chain context
								if (providerData.csSigners <= 0U)
								{
									// No signer chain context available; create object with empty chain (internally allocates new X509Chain())
									AllFileSigners.Add(new AllFileSigners(signerCertificate, IntPtr.Zero));
								}
								else
								{
									// Otherwise, get the CryptProviderSigner structure from pasSigners pointer
									if (providerData.pasSigners != IntPtr.Zero)
									{
										CryptProviderSigner signer = *(CryptProviderSigner*)providerData.pasSigners;

										// Create AllFileSigners with the native chain context pointer
										AllFileSigners.Add(new AllFileSigners(signerCertificate, signer.pChainContext));
									}
								}
							}
						}
					}
				}
			}
			finally
			{
				// Close state action if WinTrustData was allocated
				if (winTrustDataPointer != IntPtr.Zero)
				{
					// Set StateAction to close the WinTrustData structure directly in unmanaged memory
					((WinTrustData*)winTrustDataPointer)->StateAction = StateActionClose;
					_ = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref GenericWinTrustVerifyActionGuid, winTrustDataPointer);
				}

				// Free unmanaged allocations
				if (winTrustDataPointer != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(winTrustDataPointer);
				}
				if (sigSettingsPtr != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(sigSettingsPtr);
				}
				if (fileInfoPtr != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(fileInfoPtr);
				}
				if (filePathPtr != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(filePathPtr);
				}

				// Increment Index for the next signer
				Index++;
			}
		} while (Index < maxSigners + 1U);   // Continue loop until all signers are processed

		return AllFileSigners;   // Return list of all file signers
	}

}
