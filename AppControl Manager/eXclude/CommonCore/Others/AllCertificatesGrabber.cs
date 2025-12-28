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

namespace CommonCore.Others;

/// <summary>
/// The following functions and methods use the Windows APIs to grab all of the certificates from a signed file
/// </summary>
internal static class AllCertificatesGrabber
{
	// Constants related to WinTrust
	private const uint StateActionClose = 2;
	private static Guid GenericWinTrustVerifyActionGuid = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

	// This is the main method used to retrieve all signers for a given file
	internal static unsafe List<AllFileSigners> GetAllFileSigners(string FilePath, bool includeInvalidCerts = false)
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
				fileInfoPtr = Marshal.AllocHGlobal(sizeof(WINTRUST_FILE_INFO));
				WINTRUST_FILE_INFO fileInfo = new(filePathPtr);
				*(WINTRUST_FILE_INFO*)fileInfoPtr = fileInfo;

				// Build WinTrustSignatureSettings (per-signer index) in unmanaged memory
				sigSettingsPtr = Marshal.AllocHGlobal(sizeof(WINTRUST_SIGNATURE_SETTINGS));
				WINTRUST_SIGNATURE_SETTINGS sigSettings = (Index == 0)
					? new WINTRUST_SIGNATURE_SETTINGS()
					: new WINTRUST_SIGNATURE_SETTINGS(Index);
				*(WINTRUST_SIGNATURE_SETTINGS*)sigSettingsPtr = sigSettings;

				// Allocate and initialize WinTrustData
				winTrustDataPointer = Marshal.AllocHGlobal(sizeof(WINTRUST_DATA));
				WINTRUST_DATA wtd = new(fileInfoPtr, sigSettingsPtr);
				*(WINTRUST_DATA*)winTrustDataPointer = wtd;

				// Call WinVerifyTrust to verify trust on the file
				WinVerifyTrustResult verifyTrustResult = NativeMethods.WinVerifyTrust(
					IntPtr.Zero,
					ref GenericWinTrustVerifyActionGuid,
					winTrustDataPointer
				);

				// Reload updated data from unmanaged memory
				wtd = *(WINTRUST_DATA*)winTrustDataPointer;

				// Check signature settings and process the signer's certificate
				if (maxSigners == uint.MaxValue)
				{
					if (wtd.pSignatureSettings != IntPtr.Zero)
					{
						WINTRUST_SIGNATURE_SETTINGS* signatureSettings = (WINTRUST_SIGNATURE_SETTINGS*)wtd.pSignatureSettings;
						if (signatureSettings != null)
						{
							// Reading SecondarySignersCount directly from unmanaged struct
							maxSigners = signatureSettings->SecondarySignersCount;
						}
					}
				}

				// If the certificate is expired and we don't want to include invalid certs, continue to the next iteration
				if (verifyTrustResult == WinVerifyTrustResult.CertExpired && !includeInvalidCerts)
				{
					continue;
				}

				// if there is a hash mismatch in the file, throw an exception unless we want to include invalid certs
				if (verifyTrustResult == WinVerifyTrustResult.HashMismatch && !includeInvalidCerts)
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
						CommonCore.Interop.CryptProviderData providerData = *(CommonCore.Interop.CryptProviderData*)providerDataBase;

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
										CommonCore.Interop.CryptProviderSigner signer = *(CommonCore.Interop.CryptProviderSigner*)providerData.pasSigners;

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
					((WINTRUST_DATA*)winTrustDataPointer)->StateAction = StateActionClose;
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
