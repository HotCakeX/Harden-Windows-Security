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

using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Signing;

internal static class Main
{
	private static string GetHashOidFromCertSignatureAlgorithm(X509Certificate2 certificate)
	{
		string signatureAlgorithmOid = certificate.SignatureAlgorithm.Value ?? string.Empty;

		return signatureAlgorithmOid switch
		{
			// RSA Signature Algorithms to Hash OIDs
			"1.2.840.113549.1.1.5" => "1.3.14.3.2.26", // SHA1
			"1.2.840.113549.1.1.11" => "2.16.840.1.101.3.4.2.1", // SHA-2 256
			"1.2.840.113549.1.1.12" => "2.16.840.1.101.3.4.2.2", // SHA-2 384
			"1.2.840.113549.1.1.13" => "2.16.840.1.101.3.4.2.3", // SHA-2 512

			// ECDSA Signature Algorithms to Hash OIDs
			"1.2.840.10045.4.1" => "1.3.14.3.2.26", // SHA1
			"1.2.840.10045.4.3.2" => "2.16.840.1.101.3.4.2.1", // SHA-2 256
			"1.2.840.10045.4.3.3" => "2.16.840.1.101.3.4.2.2", // SHA-2 384
			"1.2.840.10045.4.3.4" => "2.16.840.1.101.3.4.2.3", // SHA-2 512

			_ => throw new NotSupportedException(string.Format(GlobalVars.GetStr("UnsupportedCertificateSignatureAlgorithmForHashOID"), signatureAlgorithmOid, certificate.SignatureAlgorithm.FriendlyName)),
		};
	}

	private static uint GetAlgIdFromCertSignatureAlgorithm(X509Certificate2 certificate)
	{
		string signatureAlgorithmOid = certificate.SignatureAlgorithm.Value ?? string.Empty;
		return signatureAlgorithmOid switch
		{
			// RSA Signature Algorithms to ALG_ID

			// sha1RSA
			"1.2.840.113549.1.1.5" => Structure.CALG_SHA1,
			// sha256RSA
			"1.2.840.113549.1.1.11" => Structure.CALG_SHA_256,
			// sha384RSA
			"1.2.840.113549.1.1.12" => Structure.CALG_SHA_384,
			// sha512RSA
			"1.2.840.113549.1.1.13" => Structure.CALG_SHA_512,

			// ECDSA Signature Algorithms to ALG_ID

			// ecdsa-with-SHA1
			"1.2.840.10045.4.1" => Structure.CALG_SHA1,
			// ecdsa-with-SHA256
			"1.2.840.10045.4.3.2" => Structure.CALG_SHA_256,
			// ecdsa-with-SHA384
			"1.2.840.10045.4.3.3" => Structure.CALG_SHA_384,
			// ecdsa-with-SHA512
			"1.2.840.10045.4.3.4" => Structure.CALG_SHA_512,

			_ => throw new NotSupportedException(string.Format(GlobalVars.GetStr("UnsupportedCertificateSignatureAlgorithmForALGID"), signatureAlgorithmOid, certificate.SignatureAlgorithm.FriendlyName)),
		};
	}

	/// <summary>
	/// Method for signing Code Integrity Policies (CIP).
	/// </summary>
	/// <param name="filePath">The CIP file to be signed.</param>
	/// <param name="CertCN"></param>
	/// <param name="Cert"></param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void SignCIP(string filePath, string? CertCN = null, X509Certificate2? Cert = null)
	{
		X509Certificate2? signingCertificate = (Cert ??
			Helper.FindCertificateBySubjectName(CertCN ??
			throw new ArgumentNullException(nameof(CertCN)))) ??
			throw new InvalidOperationException("No certificate was found");

		if (!signingCertificate.HasPrivateKey)
			throw new InvalidOperationException(GlobalVars.GetStr("CertificateMustHavePrivateKey"));

		// Read the file content to be signed
		byte[] fileContent = File.ReadAllBytes(filePath);

		// The required OID for Code Integrity policy signing.
		const string contentTypeOid = "1.3.6.1.4.1.311.79.1";

		// Create ContentInfo with the specified content type OID and file content
		ContentInfo contentInfo = new(new Oid(contentTypeOid), fileContent);

		SignedCms signedCms = new(contentInfo, false);

		// Configure the signer with the certificate
		CmsSigner signer = new(signingCertificate);

		// Set the digest algorithm based on the certificate's signature algorithm
		string hashOid = GetHashOidFromCertSignatureAlgorithm(signingCertificate);
		signer.DigestAlgorithm = new Oid(hashOid);

		// Include only the signing certificate
		signer.IncludeOption = X509IncludeOption.EndCertOnly;

		signer.SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber; // Required

		// Compute the signature
		// Using the silent feature would throw error when the following group policy is in effect:
		// System Cryptography: Force strong key protection for user keys stored on the computer
		signedCms.ComputeSignature(signer, false);

		// Encode the signed PKCS #7 message
		byte[] signedBytes = signedCms.Encode();

		ForceCmsVersionToV1(signedBytes);

		File.Delete(filePath);
		File.WriteAllBytes(filePath, signedBytes);

		Logger.Write(string.Format(GlobalVars.GetStr("PKCS7SignatureWritten"), filePath));
	}

	/// <summary>
	/// Forces the CMS version to v1 by patching the ASN.1 encoded data.
	/// </summary>
	private static void ForceCmsVersionToV1(Span<byte> data)
	{
		// PKCS#7 SignedData structure:
		// SEQUENCE (0x30)
		//   OID for signedData (1.2.840.113549.1.7.2)
		//   [0] EXPLICIT (0xA0)
		//     SEQUENCE (0x30)
		//       INTEGER version (0x02)
		//         length
		//         value (we want to change this from 03 to 01)

		int index = 0;

		// Skip the outer SEQUENCE tag and length
		if (data[index] == 0x30) // SEQUENCE tag
		{
			index++;
			// Skip length bytes (do not skip the SEQUENCE value itself)
			if ((data[index] & 0x80) != 0)
			{
				int lengthBytes = data[index] & 0x7F;
				index += lengthBytes + 1;
			}
			else
			{
				index++;
			}

			// Look for signedData OID: 06 09 2A 86 48 86 F7 0D 01 07 02
			if (data[index] == 0x06 && data[index + 1] == 0x09)
			{
				// Verify it's the signedData OID
				ReadOnlySpan<byte> signedDataOid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

				bool isSignedData = data.Slice(index + 2, 9).SequenceEqual(signedDataOid);

				if (isSignedData)
				{
					index += 11; // Skip OID (1 tag + 1 length + 9 value)

					// Should now be at [0] EXPLICIT tag (0xA0)
					if (data[index] == 0xA0)
					{
						index++;
						// Skip length bytes
						if ((data[index] & 0x80) != 0)
						{
							int lengthBytes = data[index] & 0x7F;
							index += lengthBytes + 1;
						}
						else
						{
							index++;
						}

						// Should now be at inner SEQUENCE (0x30)
						if (data[index] == 0x30)
						{
							index++;
							// Skip length bytes
							if ((data[index] & 0x80) != 0)
							{
								int lengthBytes = data[index] & 0x7F;
								index += lengthBytes + 1;
							}
							else
							{
								index++;
							}

							// Should now be at INTEGER tag for version (0x02)
							if (data[index] == 0x02)
							{
								index++;
								_ = data[index]; // length
								index++;

								// Now at the version value - change it to 1
								if (data[index] == 0x03) // If it's version 3
								{
									data[index] = 0x01; // Change to version 1
								}
							}
						}
					}
				}
			}
		}
	}

	/// <summary>
	/// Method for signing regular PE files.
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="signingCertificate"></param>
	/// <param name="timestampUrl"></param>
	/// <param name="enablePageHashing"></param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="Win32Exception"></exception>
	private static unsafe void SignFilePE(string FilePath,
								   X509Certificate2 signingCertificate,
								   string? timestampUrl = null,
								   bool enablePageHashing = false)
	{
		if (string.IsNullOrEmpty(FilePath))
			throw new ArgumentNullException(nameof(FilePath));

		ArgumentNullException.ThrowIfNull(signingCertificate);

		if (!signingCertificate.HasPrivateKey)
			throw new ArgumentException(GlobalVars.GetStr("CertificateMustHavePrivateKey"), nameof(signingCertificate));

		IntPtr pSignerFileInfo = IntPtr.Zero;
		IntPtr pSignerSubjectInfo = IntPtr.Zero;
		IntPtr pSignerIndex = IntPtr.Zero;
		IntPtr pSignerCertStoreInfo = IntPtr.Zero;
		IntPtr pSignerCert = IntPtr.Zero;
		IntPtr pSignerSignatureInfo = IntPtr.Zero;
		IntPtr ppSignerContext = IntPtr.Zero;
		IntPtr pActualSignerContext = IntPtr.Zero;

		// Track unmanaged allocation of the wide string for file name
		IntPtr pFileNameString = IntPtr.Zero;

		try
		{
			// Allocate and initialize signer index (DWORD)
			uint signerIndex = 0;
			pSignerIndex = Marshal.AllocHGlobal(sizeof(uint));
			*(uint*)pSignerIndex = signerIndex;

			// SIGNER_FILE_INFO
			int fileInfoSize = sizeof(Structure.SIGNER_FILE_INFO);
			pSignerFileInfo = Marshal.AllocHGlobal(fileInfoSize);
			Structure.SIGNER_FILE_INFO* pFileInfo = (Structure.SIGNER_FILE_INFO*)pSignerFileInfo;
			pFileInfo->cbSize = (uint)fileInfoSize;
			pFileNameString = Marshal.StringToHGlobalUni(FilePath); // unmanaged LPCWSTR
			pFileInfo->pwszFileName = pFileNameString;
			pFileInfo->hFile = IntPtr.Zero;

			// SIGNER_SUBJECT_INFO
			int subjectInfoSize = sizeof(Structure.SIGNER_SUBJECT_INFO);
			pSignerSubjectInfo = Marshal.AllocHGlobal(subjectInfoSize);
			Structure.SIGNER_SUBJECT_INFO* pSubjectInfo = (Structure.SIGNER_SUBJECT_INFO*)pSignerSubjectInfo;
			pSubjectInfo->cbSize = (uint)subjectInfoSize;
			pSubjectInfo->pdwIndex = pSignerIndex;
			pSubjectInfo->dwSubjectChoice = Structure.SIGNER_SUBJECT_FILE;
			pSubjectInfo->Info.pSignerFileInfo = pSignerFileInfo;

			// SIGNER_CERT_STORE_INFO
			int certStoreInfoSize = sizeof(Structure.SIGNER_CERT_STORE_INFO);
			pSignerCertStoreInfo = Marshal.AllocHGlobal(certStoreInfoSize);
			Structure.SIGNER_CERT_STORE_INFO* pCertStoreInfo = (Structure.SIGNER_CERT_STORE_INFO*)pSignerCertStoreInfo;
			pCertStoreInfo->cbSize = (uint)certStoreInfoSize;
			pCertStoreInfo->pSigningCert = signingCertificate.Handle;
			pCertStoreInfo->dwCertPolicy = Structure.SIGNER_CERT_POLICY_CHAIN_NO_ROOT;
			pCertStoreInfo->hCertStore = IntPtr.Zero;

			// SIGNER_CERT
			int signerCertSize = sizeof(Structure.SIGNER_CERT);
			pSignerCert = Marshal.AllocHGlobal(signerCertSize);
			Structure.SIGNER_CERT* pSignerCertStruct = (Structure.SIGNER_CERT*)pSignerCert;
			pSignerCertStruct->cbSize = (uint)signerCertSize;
			pSignerCertStruct->dwCertChoice = Structure.SIGNER_CERT_STORE;
			pSignerCertStruct->CertChoice.pCertStoreInfo = pSignerCertStoreInfo;
			pSignerCertStruct->hwnd = IntPtr.Zero;

			// SIGNER_SIGNATURE_INFO
			int sigInfoSize = sizeof(Structure.SIGNER_SIGNATURE_INFO);
			pSignerSignatureInfo = Marshal.AllocHGlobal(sigInfoSize);
			Structure.SIGNER_SIGNATURE_INFO* pSigInfo = (Structure.SIGNER_SIGNATURE_INFO*)pSignerSignatureInfo;
			pSigInfo->cbSize = (uint)sigInfoSize;
			pSigInfo->algidHash = GetAlgIdFromCertSignatureAlgorithm(signingCertificate);
			pSigInfo->dwAttrChoice = Structure.SIGNER_NO_ATTR;
			pSigInfo->Attr.pAttrAuthcode = IntPtr.Zero;
			pSigInfo->psAuthenticated = IntPtr.Zero;
			pSigInfo->psUnauthenticated = IntPtr.Zero;

			// PSIGNER_CONTEXT*
			ppSignerContext = Marshal.AllocHGlobal(IntPtr.Size);
			Marshal.WriteIntPtr(ppSignerContext, IntPtr.Zero);

			// Flags
			uint dwFlags = 0;
			if (enablePageHashing)
			{
				dwFlags |= Structure.SPC_INC_PE_PAGE_HASHES_FLAG;
			}

			IntPtr pSipData = IntPtr.Zero;

			int hr = NativeMethods.SignerSignEx3(
				dwFlags,
				pSignerSubjectInfo,
				pSignerCert,
				pSignerSignatureInfo,
				IntPtr.Zero,
				0,
				null,
				timestampUrl,
				IntPtr.Zero,
				pSipData,
				ppSignerContext,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero
			);

			if (hr != Structure.S_OK) // S_OK is 0
			{
				string errorMessage = string.Format(GlobalVars.GetStr("SignerSignEx3Failed"), hr);

				if (hr == Structure.ERROR_BAD_FORMAT_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorBadFormat");
				else if (hr == Structure.ERROR_FILE_NOT_FOUND_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorFileNotFound");
				else if (hr == Structure.E_INVALIDARG_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorInvalidArg");

				throw new Win32Exception(hr, errorMessage);
			}

			// Retrieve the actual SIGNER_CONTEXT pointer from the memory location pointed to by ppSignerContext
			pActualSignerContext = Marshal.ReadIntPtr(ppSignerContext);
			// File is now signed.
		}
		finally
		{
			if (pActualSignerContext != IntPtr.Zero)
				_ = NativeMethods.SignerFreeSignerContext(pActualSignerContext);

			if (ppSignerContext != IntPtr.Zero)
				Marshal.FreeHGlobal(ppSignerContext);

			// Cleanup for Authenticode common structures
			if (pSignerSignatureInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSignatureInfo);
			if (pSignerCert != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCert);
			if (pSignerCertStoreInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCertStoreInfo);
			if (pSignerSubjectInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSubjectInfo);
			if (pSignerIndex != IntPtr.Zero) Marshal.FreeHGlobal(pSignerIndex);
			if (pSignerFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerFileInfo);
			if (pFileNameString != IntPtr.Zero) Marshal.FreeHGlobal(pFileNameString);
		}
	}

	/// <summary>
	/// Method for signing packaged files (AppX/MSIX)
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="signingCertificate"></param>
	/// <param name="timestampUrl"></param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="Win32Exception"></exception>
	private static unsafe void SignFilePackage(string FilePath,
										X509Certificate2 signingCertificate,
										string? timestampUrl = null)
	{
		if (string.IsNullOrEmpty(FilePath))
			throw new ArgumentNullException(nameof(FilePath));

		ArgumentNullException.ThrowIfNull(signingCertificate);

		if (!signingCertificate.HasPrivateKey)
			throw new ArgumentException(GlobalVars.GetStr("CertificateMustHavePrivateKey"), nameof(signingCertificate));

		IntPtr pSignerFileInfo = IntPtr.Zero;
		IntPtr pSignerSubjectInfo = IntPtr.Zero;
		IntPtr pSignerIndex = IntPtr.Zero;
		IntPtr pSignerCertStoreInfo = IntPtr.Zero;
		IntPtr pSignerCert = IntPtr.Zero;
		IntPtr pSignerSignatureInfo = IntPtr.Zero;
		IntPtr ppSignerContext = IntPtr.Zero;      // This will be a pointer to where the actual context pointer is stored
		IntPtr pActualSignerContext = IntPtr.Zero; // This will hold the actual SIGNER_CONTEXT handle

		// Specific to Package mode
		IntPtr pAppxSipClientData = IntPtr.Zero;
		IntPtr pLegacySignerEx3ParamsForSip = IntPtr.Zero; // This points to a SIGNER_SIGN_EX3_PARAMS struct for SIP
		IntPtr pSipData = IntPtr.Zero;                     // This will be set to pAppxSipClientData for Package mode

		// Track unmanaged allocation of file name string
		IntPtr pFileNameString = IntPtr.Zero;

		try
		{
			// Set up signer index
			uint signerIndex = 0;
			pSignerIndex = Marshal.AllocHGlobal(sizeof(uint));
			*(uint*)pSignerIndex = signerIndex;

			// SIGNER_FILE_INFO
			int fileInfoSize = sizeof(Structure.SIGNER_FILE_INFO);
			pSignerFileInfo = Marshal.AllocHGlobal(fileInfoSize);
			Structure.SIGNER_FILE_INFO* pFileInfo = (Structure.SIGNER_FILE_INFO*)pSignerFileInfo;
			pFileInfo->cbSize = (uint)fileInfoSize;
			pFileNameString = Marshal.StringToHGlobalUni(FilePath);
			pFileInfo->pwszFileName = pFileNameString;
			pFileInfo->hFile = IntPtr.Zero;

			// SIGNER_SUBJECT_INFO
			int subjectInfoSize = sizeof(Structure.SIGNER_SUBJECT_INFO);
			pSignerSubjectInfo = Marshal.AllocHGlobal(subjectInfoSize);
			Structure.SIGNER_SUBJECT_INFO* pSubjectInfo = (Structure.SIGNER_SUBJECT_INFO*)pSignerSubjectInfo;
			pSubjectInfo->cbSize = (uint)subjectInfoSize;
			pSubjectInfo->pdwIndex = pSignerIndex;
			pSubjectInfo->dwSubjectChoice = Structure.SIGNER_SUBJECT_FILE; // AppX SIP uses file-based subject
			pSubjectInfo->Info.pSignerFileInfo = pSignerFileInfo;

			// SIGNER_CERT_STORE_INFO
			int certStoreInfoSize = sizeof(Structure.SIGNER_CERT_STORE_INFO);
			pSignerCertStoreInfo = Marshal.AllocHGlobal(certStoreInfoSize);
			Structure.SIGNER_CERT_STORE_INFO* pCertStoreInfo = (Structure.SIGNER_CERT_STORE_INFO*)pSignerCertStoreInfo;
			pCertStoreInfo->cbSize = (uint)certStoreInfoSize;
			pCertStoreInfo->pSigningCert = signingCertificate.Handle;
			pCertStoreInfo->dwCertPolicy = Structure.SIGNER_CERT_POLICY_CHAIN_NO_ROOT;
			pCertStoreInfo->hCertStore = IntPtr.Zero;

			// SIGNER_CERT
			int signerCertSize = sizeof(Structure.SIGNER_CERT);
			pSignerCert = Marshal.AllocHGlobal(signerCertSize);
			Structure.SIGNER_CERT* pSignerCertStruct = (Structure.SIGNER_CERT*)pSignerCert;
			pSignerCertStruct->cbSize = (uint)signerCertSize;
			pSignerCertStruct->dwCertChoice = Structure.SIGNER_CERT_STORE;
			pSignerCertStruct->CertChoice.pCertStoreInfo = pSignerCertStoreInfo;
			pSignerCertStruct->hwnd = IntPtr.Zero;

			// SIGNER_SIGNATURE_INFO
			int sigInfoSize = sizeof(Structure.SIGNER_SIGNATURE_INFO);
			pSignerSignatureInfo = Marshal.AllocHGlobal(sigInfoSize);
			Structure.SIGNER_SIGNATURE_INFO* pSigInfo = (Structure.SIGNER_SIGNATURE_INFO*)pSignerSignatureInfo;
			pSigInfo->cbSize = (uint)sigInfoSize;
			pSigInfo->algidHash = GetAlgIdFromCertSignatureAlgorithm(signingCertificate);
			pSigInfo->dwAttrChoice = Structure.SIGNER_NO_ATTR; // No authenticated attributes for Package signing in this path
			pSigInfo->Attr.pAttrAuthcode = IntPtr.Zero;
			pSigInfo->psAuthenticated = IntPtr.Zero;
			pSigInfo->psUnauthenticated = IntPtr.Zero;

			// PSIGNER_CONTEXT*
			ppSignerContext = Marshal.AllocHGlobal(IntPtr.Size);
			Marshal.WriteIntPtr(ppSignerContext, IntPtr.Zero);

			// SIGNER_SIGN_EX3_PARAMS for SIP (subset we need)
			int ex3ParamsSize = sizeof(Structure.SIGNER_SIGN_EX3_PARAMS);
			pLegacySignerEx3ParamsForSip = Marshal.AllocHGlobal(ex3ParamsSize);
			Structure.SIGNER_SIGN_EX3_PARAMS* pEx3 = (Structure.SIGNER_SIGN_EX3_PARAMS*)pLegacySignerEx3ParamsForSip;

			// Zero memory (defensive)
			for (int i = 0; i < ex3ParamsSize / sizeof(int); i++)
			{
				((int*)pEx3)[i] = 0;
			}

			pEx3->pSubjectInfo = pSignerSubjectInfo;
			pEx3->pSigningCert = pSignerCert;
			pEx3->pSignatureInfo = pSignerSignatureInfo;

			// APPX_SIP_CLIENT_DATA
			int sipClientDataSize = sizeof(Structure.APPX_SIP_CLIENT_DATA);
			pAppxSipClientData = Marshal.AllocHGlobal(sipClientDataSize);
			Structure.APPX_SIP_CLIENT_DATA* pSipClientData = (Structure.APPX_SIP_CLIENT_DATA*)pAppxSipClientData;
			pSipClientData->pSignerParams = pLegacySignerEx3ParamsForSip;
			pSipClientData->pAppxSipState = IntPtr.Zero;

			pSipData = pAppxSipClientData; // Use prepared SIP data

			uint dwFlags = 0; // Page hashing flag not used for packages

			int hr = NativeMethods.SignerSignEx3(
				dwFlags,        // dwFlags
				pSignerSubjectInfo,
				pSignerCert,
				pSignerSignatureInfo,
				IntPtr.Zero,    // pProviderInfo
				0,              // dwTimestampFlags
				null,           // pszTimestampAlgorithmOid
				timestampUrl,   // pwszHttpTimeStamp
				IntPtr.Zero,    // psRequest
				pSipData,       // pSipData
				ppSignerContext,// PSIGNER_CONTEXT*
				IntPtr.Zero,    // pCryptoPolicy
				IntPtr.Zero,    // pSignEx3Params
				IntPtr.Zero     // ppReserved
			);

			if (hr != Structure.S_OK)
			{
				string errorMessage = string.Format(GlobalVars.GetStr("SignerSignEx3Failed"), hr);

				if (hr == Structure.ERROR_BAD_FORMAT_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorBadFormat");
				else if (hr == Structure.ERROR_FILE_NOT_FOUND_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorFileNotFound");
				else if (hr == Structure.E_INVALIDARG_HRESULT)
					errorMessage += GlobalVars.GetStr("ErrorInvalidArg");

				throw new Win32Exception(hr, errorMessage);
			}

			pActualSignerContext = Marshal.ReadIntPtr(ppSignerContext);
			// Package is now signed.

			if (pAppxSipClientData != IntPtr.Zero)
			{
				// Read back updated SIP state
				Structure.APPX_SIP_CLIENT_DATA finalSipClientData = *(Structure.APPX_SIP_CLIENT_DATA*)pAppxSipClientData;
				if (finalSipClientData.pAppxSipState != IntPtr.Zero)
				{
					IntPtr pUnk = finalSipClientData.pAppxSipState;
					IntPtr pVtbl = Marshal.ReadIntPtr(pUnk, 0); // VTable pointer
					Structure.IUnknownVtbl vtbl = *(Structure.IUnknownVtbl*)pVtbl;
					Structure.Release_Delegate releaseDelegate =
						Marshal.GetDelegateForFunctionPointer<Structure.Release_Delegate>(vtbl.Release);
					_ = releaseDelegate(pUnk); // Call Release
				}
			}
		}
		finally
		{
			if (pActualSignerContext != IntPtr.Zero)
				_ = NativeMethods.SignerFreeSignerContext(pActualSignerContext);

			if (ppSignerContext != IntPtr.Zero)
				Marshal.FreeHGlobal(ppSignerContext);

			if (pAppxSipClientData != IntPtr.Zero)
				Marshal.FreeHGlobal(pAppxSipClientData);

			if (pLegacySignerEx3ParamsForSip != IntPtr.Zero)
				Marshal.FreeHGlobal(pLegacySignerEx3ParamsForSip);

			// Cleanup for Authenticode common structures
			if (pSignerSignatureInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSignatureInfo);
			if (pSignerCert != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCert);
			if (pSignerCertStoreInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCertStoreInfo);
			if (pSignerSubjectInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSubjectInfo);
			if (pSignerIndex != IntPtr.Zero) Marshal.FreeHGlobal(pSignerIndex);
			if (pSignerFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerFileInfo);
			if (pFileNameString != IntPtr.Zero) Marshal.FreeHGlobal(pFileNameString);
		}
	}

	/// <summary>
	/// Signs an App Package.
	/// </summary>
	/// <param name="PackagePath"></param>
	/// <param name="Cert"></param>
	internal static void SignAppPackage(string PackagePath, X509Certificate2 Cert)
	{
		try
		{
			SignFilePackage(PackagePath, Cert, null);
		}
		catch (Win32Exception w32Ex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("Win32ErrorSigningFile"), w32Ex.NativeErrorCode, w32Ex.NativeErrorCode, w32Ex.Message));

			throw;
		}
	}

	/// <summary>
	/// Signs normal PEs.
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="Cert"></param>
	/// <param name="CertCN"></param>
	/// <exception cref="ArgumentNullException"></exception>
	internal static void SignPEs(string FilePath, X509Certificate2? Cert, string? CertCN)
	{
		try
		{
			// Use the Cert obj if provided, else find the certificate based on the provided subject CN
			X509Certificate2? cert = Cert ?? Helper.FindCertificateBySubjectName(CertCN ?? throw new ArgumentNullException(nameof(CertCN)));

			SignFilePE(FilePath, cert!, null, true);
		}
		catch (Win32Exception w32Ex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("Win32ErrorSigningFile"), w32Ex.NativeErrorCode, w32Ex.NativeErrorCode, w32Ex.Message));

			throw;
		}
	}

}
