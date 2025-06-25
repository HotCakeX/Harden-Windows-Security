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

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Others;

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
	/// Method for SigningMode.Blob, CIP files. Problem with it is that it generates CMS V3
	/// but then the signed CIP files will not be authorized by the OS after deployment
	/// since they need CMS V1 which is less secure and not compatible with CNG.
	/// </summary>
	/// <param name="filePath"></param>
	/// <param name="signingCertificate"></param>
	/// <param name="contentOid"></param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	private static void SignFileBlob(string filePath,
									  X509Certificate2 signingCertificate,
									  string? contentOid = null)
	{
		if (string.IsNullOrEmpty(filePath))
			throw new ArgumentNullException(nameof(filePath));

		ArgumentNullException.ThrowIfNull(signingCertificate);

		if (!signingCertificate.HasPrivateKey)
			throw new ArgumentException(GlobalVars.GetStr("CertificateMustHavePrivateKey"), nameof(signingCertificate));

		// Read the file content to be signed
		byte[] fileContent = File.ReadAllBytes(filePath);

		// Determine the content type OID; default to PKCS #7 Data if not specified
		string contentTypeOid = contentOid ?? "1.2.840.113549.1.7.1";

		// Create ContentInfo with the specified content type OID and file content
		ContentInfo contentInfo = new(new Oid(contentTypeOid), fileContent);

		// Initialize SignedCms with attached content (not detached)
		SignedCms signedCms = new(contentInfo, false);

		// Configure the signer with the certificate
		CmsSigner signer = new(signingCertificate);

		// Set the digest algorithm based on the certificate's signature algorithm
		string hashOid = GetHashOidFromCertSignatureAlgorithm(signingCertificate);
		signer.DigestAlgorithm = new Oid(hashOid);

		// Include only the signing certificate
		signer.IncludeOption = X509IncludeOption.EndCertOnly;

		// Compute the signature
		// Using the silent feature would throw error when the following group policy is in effect:
		// System Cryptography: Force strong key protection for user keys stored on the computer
		signedCms.ComputeSignature(signer, false);

		// Encode the signed PKCS #7 message
		byte[] signedBytes = signedCms.Encode();

		// Replace the original file with the signed content
		File.Delete(filePath);
		File.WriteAllBytes(filePath, signedBytes);

		Logger.Write(string.Format(GlobalVars.GetStr("PKCS7SignatureWritten"), filePath));
	}

	/// <summary>
	/// Method for signings regular PE files
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="signingCertificate"></param>
	/// <param name="timestampUrl"></param>
	/// <param name="enablePageHashing"></param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="Win32Exception"></exception>
	private static void SignFilePE(string FilePath,
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

		try
		{
			// Set up signer index
			uint signerIndex = 0;
			pSignerIndex = Marshal.AllocHGlobal(Marshal.SizeOf(signerIndex));
			Marshal.WriteInt32(pSignerIndex, (int)signerIndex);

			Structure.SIGNER_FILE_INFO fileInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_FILE_INFO>(),
				pwszFileName = FilePath,
				hFile = IntPtr.Zero
			};
			pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
			Marshal.StructureToPtr(fileInfo, pSignerFileInfo, false);

			Structure.SIGNER_SUBJECT_INFO subjectInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_SUBJECT_INFO>(),
				pdwIndex = pSignerIndex,
				dwSubjectChoice = Structure.SIGNER_SUBJECT_FILE
			};
			subjectInfo.Info.pSignerFileInfo = pSignerFileInfo;
			pSignerSubjectInfo = Marshal.AllocHGlobal(Marshal.SizeOf(subjectInfo));
			Marshal.StructureToPtr(subjectInfo, pSignerSubjectInfo, false);

			Structure.SIGNER_CERT_STORE_INFO certStoreInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_CERT_STORE_INFO>(),
				pSigningCert = signingCertificate.Handle,
				dwCertPolicy = Structure.SIGNER_CERT_POLICY_CHAIN_NO_ROOT, // Standard policy
				hCertStore = IntPtr.Zero // No additional cert store
			};
			pSignerCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certStoreInfo));
			Marshal.StructureToPtr(certStoreInfo, pSignerCertStoreInfo, false);

			Structure.SIGNER_CERT signerCert = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_CERT>(),
				dwCertChoice = Structure.SIGNER_CERT_STORE, // Use cert store info
				hwnd = IntPtr.Zero // No UI
			};
			signerCert.CertChoice.pCertStoreInfo = pSignerCertStoreInfo;
			pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf(signerCert));
			Marshal.StructureToPtr(signerCert, pSignerCert, false);

			uint algId = GetAlgIdFromCertSignatureAlgorithm(signingCertificate);

			Structure.SIGNER_SIGNATURE_INFO signatureInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_SIGNATURE_INFO>(),
				algidHash = algId,
				dwAttrChoice = Structure.SIGNER_NO_ATTR,
				psAuthenticated = IntPtr.Zero,
				psUnauthenticated = IntPtr.Zero
			};

			pSignerSignatureInfo = Marshal.AllocHGlobal(Marshal.SizeOf(signatureInfo));
			Marshal.StructureToPtr(signatureInfo, pSignerSignatureInfo, false);

			ppSignerContext = Marshal.AllocHGlobal(IntPtr.Size);
			Marshal.WriteIntPtr(ppSignerContext, IntPtr.Zero);

			// For SigningMode.File, pSipData remains IntPtr.Zero, letting the system find a SIP if applicable.
			IntPtr pSipData = IntPtr.Zero;

			// Set dwFlags based on enablePageHashing
			uint dwFlags = 0;
			if (enablePageHashing)
			{
				dwFlags |= Structure.SPC_INC_PE_PAGE_HASHES_FLAG;
			}

			int hr = NativeMethods.SignerSignEx3(
				dwFlags,               // dwFlags for page hashing etc.
				pSignerSubjectInfo,
				pSignerCert,
				pSignerSignatureInfo,
				IntPtr.Zero,           // pProviderInfo (NULL for default CSP)
				0,                     // dwTimestampFlags (0 for no timestamp by default, or specific flags if URL is used)
				null,                  // pszTimestampAlgorithmOid (for timestamp, if dwTimestampFlags is set)
				timestampUrl,          // pwszHttpTimeStamp
				IntPtr.Zero,           // psRequest (for timestamp server attributes)
				pSipData,              // pSipData (IntPtr.Zero for PE files unless specific SIP is used)
				ppSignerContext,       // PSIGNER_CONTEXT* (pointer to where the context pointer will be written)
				IntPtr.Zero,           // pCryptoPolicy (NULL for default)
				IntPtr.Zero,           // pSignEx3Params (this is the 13th param, original code passed IntPtr.Zero)
				IntPtr.Zero            // ppReserved (must be NULL)
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
			if (ppSignerContext != IntPtr.Zero) Marshal.FreeHGlobal(ppSignerContext); // Free the memory allocated for the pointer itself

			// Cleanup for Authenticode common structures
			if (pSignerSignatureInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSignatureInfo);
			if (pSignerCert != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCert);
			if (pSignerCertStoreInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCertStoreInfo);
			if (pSignerSubjectInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSubjectInfo);
			if (pSignerIndex != IntPtr.Zero) Marshal.FreeHGlobal(pSignerIndex);
			if (pSignerFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerFileInfo);
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
	private static void SignFilePackage(string FilePath,
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

		try
		{
			// Set up signer index
			uint signerIndex = 0;
			pSignerIndex = Marshal.AllocHGlobal(Marshal.SizeOf(signerIndex));
			Marshal.WriteInt32(pSignerIndex, (int)signerIndex);

			Structure.SIGNER_FILE_INFO fileInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_FILE_INFO>(),
				pwszFileName = FilePath,
				hFile = IntPtr.Zero
			};
			pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
			Marshal.StructureToPtr(fileInfo, pSignerFileInfo, false);

			Structure.SIGNER_SUBJECT_INFO subjectInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_SUBJECT_INFO>(),
				pdwIndex = pSignerIndex,
				dwSubjectChoice = Structure.SIGNER_SUBJECT_FILE // AppX SIP uses file-based subject
			};
			subjectInfo.Info.pSignerFileInfo = pSignerFileInfo;
			pSignerSubjectInfo = Marshal.AllocHGlobal(Marshal.SizeOf(subjectInfo));
			Marshal.StructureToPtr(subjectInfo, pSignerSubjectInfo, false);

			Structure.SIGNER_CERT_STORE_INFO certStoreInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_CERT_STORE_INFO>(),
				pSigningCert = signingCertificate.Handle,
				dwCertPolicy = Structure.SIGNER_CERT_POLICY_CHAIN_NO_ROOT,
				hCertStore = IntPtr.Zero
			};
			pSignerCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certStoreInfo));
			Marshal.StructureToPtr(certStoreInfo, pSignerCertStoreInfo, false);

			Structure.SIGNER_CERT signerCert = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_CERT>(),
				dwCertChoice = Structure.SIGNER_CERT_STORE,
				hwnd = IntPtr.Zero
			};
			signerCert.CertChoice.pCertStoreInfo = pSignerCertStoreInfo;
			pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf(signerCert));
			Marshal.StructureToPtr(signerCert, pSignerCert, false);

			uint algId = GetAlgIdFromCertSignatureAlgorithm(signingCertificate);

			Structure.SIGNER_SIGNATURE_INFO signatureInfo = new()
			{
				cbSize = (uint)Marshal.SizeOf<Structure.SIGNER_SIGNATURE_INFO>(),
				algidHash = algId,
				dwAttrChoice = Structure.SIGNER_NO_ATTR, // No authenticated attributes for Package signing in this path
				psAuthenticated = IntPtr.Zero,
				psUnauthenticated = IntPtr.Zero
			};

			pSignerSignatureInfo = Marshal.AllocHGlobal(Marshal.SizeOf(signatureInfo));
			Marshal.StructureToPtr(signatureInfo, pSignerSignatureInfo, false);

			ppSignerContext = Marshal.AllocHGlobal(IntPtr.Size);
			Marshal.WriteIntPtr(ppSignerContext, IntPtr.Zero);

			// Specific setup for Package mode (AppX/MSIX SIP)
			// The SIGNER_SIGN_EX3_PARAMS struct is what APPX_SIP_CLIENT_DATA.pSignerParams points to.
			pLegacySignerEx3ParamsForSip = Marshal.AllocHGlobal(Marshal.SizeOf<Structure.SIGNER_SIGN_EX3_PARAMS>());
			Structure.SIGNER_SIGN_EX3_PARAMS signerEx3ParamsStructForSip = new()
			{
				pSubjectInfo = pSignerSubjectInfo,
				pSigningCert = pSignerCert,
				pSignatureInfo = pSignerSignatureInfo,
				pProviderInfo = IntPtr.Zero,
			};
			Marshal.StructureToPtr(signerEx3ParamsStructForSip, pLegacySignerEx3ParamsForSip, false);

			pAppxSipClientData = Marshal.AllocHGlobal(Marshal.SizeOf<Structure.APPX_SIP_CLIENT_DATA>());
			Structure.APPX_SIP_CLIENT_DATA appxSipClientDataStruct = new()
			{
				pSignerParams = pLegacySignerEx3ParamsForSip, // This is PSIGNER_SIGN_EX3_PARAMS
				pAppxSipState = IntPtr.Zero // To be filled by SIP
			};
			Marshal.StructureToPtr(appxSipClientDataStruct, pAppxSipClientData, false);
			pSipData = pAppxSipClientData; // Use the prepared SIP data for AppX/MSIX

			uint dwFlags = 0; // Page hashing (SPC_INC_PE_PAGE_HASHES_FLAG) is not applicable for packages.

			int hr = NativeMethods.SignerSignEx3(
				dwFlags,        // Main dwFlags for SignerSignEx3, usually 0 for packages.
				pSignerSubjectInfo,
				pSignerCert,
				pSignerSignatureInfo,
				IntPtr.Zero,    // pProviderInfo
				0,              // dwTimestampFlags for SignerSignEx3 function
				null,           // pszTimestampAlgorithmOid for SignerSignEx3 function
				timestampUrl,   // pwszHttpTimeStamp for SignerSignEx3 function
				IntPtr.Zero,    // psRequest
				pSipData,       // Pass pSipData (which is pAppxSipClientData)
				ppSignerContext,// PSIGNER_CONTEXT*
				IntPtr.Zero,    // pCryptoPolicy
				IntPtr.Zero,    // pSignEx3Params (13th param, usually for non-SIP advanced scenarios or overrides)
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

			if (pAppxSipClientData != IntPtr.Zero) // pSipData is pAppxSipClientData here
			{
				// Re-read the struct from pAppxSipClientData in case SIP modified pAppxSipState
				Structure.APPX_SIP_CLIENT_DATA finalSipClientData =
					Marshal.PtrToStructure<Structure.APPX_SIP_CLIENT_DATA>(pAppxSipClientData);

				if (finalSipClientData.pAppxSipState != IntPtr.Zero)
				{
					IntPtr pUnk = finalSipClientData.pAppxSipState;
					IntPtr pVtbl = Marshal.ReadIntPtr(pUnk, 0); // Read the VTable pointer from the object's first field
					Structure.IUnknownVtbl vtbl = Marshal.PtrToStructure<Structure.IUnknownVtbl>(pVtbl);

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
			if (ppSignerContext != IntPtr.Zero) Marshal.FreeHGlobal(ppSignerContext);

			if (pAppxSipClientData != IntPtr.Zero) Marshal.FreeHGlobal(pAppxSipClientData);
			if (pLegacySignerEx3ParamsForSip != IntPtr.Zero) Marshal.FreeHGlobal(pLegacySignerEx3ParamsForSip);

			// Cleanup for Authenticode common structures
			if (pSignerSignatureInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSignatureInfo);
			if (pSignerCert != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCert);
			if (pSignerCertStoreInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerCertStoreInfo);
			if (pSignerSubjectInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerSubjectInfo);
			if (pSignerIndex != IntPtr.Zero) Marshal.FreeHGlobal(pSignerIndex);
			if (pSignerFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pSignerFileInfo);
		}
	}


	/// <summary>
	/// Signs a CIP Code Integrity policy file.
	/// </summary>
	/// <param name="CIPPath"></param>
	/// <param name="CertCN"></param>
	internal static void SignCIPUnUsed(string CIPPath, string CertCN)
	{
		X509Certificate2? cert = null;

		try
		{
			// Find the certificate based on the provided subject CN
			cert = Helper.FindCertificateBySubjectName(CertCN);

			SignFileBlob(CIPPath, cert!, Structure.CodeIntegrityOID);
		}
		catch (Win32Exception w32Ex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("Win32ErrorSigningFile"), w32Ex.NativeErrorCode, w32Ex.NativeErrorCode, w32Ex.Message));

			throw;
		}
		finally
		{
			cert?.Dispose();
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
