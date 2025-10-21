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

using System.Runtime.InteropServices;

namespace AppControlManager.Signing;

/// <summary>
/// Defines the main structure of the signing operations. Defines C constants.
/// Learn more by following the links below.
/// https://learn.microsoft.com/windows/win32/appxpkg/how-to-programmatically-sign-a-package
/// https://learn.microsoft.com/windows/win32/seccrypto/signersignex3
/// </summary>
internal static class Structure
{
	// https://learn.microsoft.com/windows/win32/seccrypto/signer-subject-info
	internal const uint SIGNER_SUBJECT_FILE = 0x01;
	internal const uint SIGNER_SUBJECT_BLOB = 0x02;

	// https://learn.microsoft.com/windows/win32/seccrypto/signer-signature-info
	internal const uint SIGNER_NO_ATTR = 0x00;
	internal const uint SIGNER_AUTHCODE_ATTR = 0x01;

	// https://learn.microsoft.com/windows/win32/seccrypto/signer-provider-info
	internal const uint PVK_TYPE_FILE_NAME = 0x01;
	internal const uint PVK_TYPE_KEYCONTAINER = 0x02;

	// https://learn.microsoft.com/windows/win32/seccrypto/signer-cert-store-info
	// dwCertPolicy can be a combination of the following flags:
	internal const uint SIGNER_CERT_POLICY_STORE = 0x01;
	internal const uint SIGNER_CERT_POLICY_CHAIN = 0x02;
	internal const uint SIGNER_CERT_POLICY_SPC = 0x04;
	internal const uint SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 0x08;

	// https://learn.microsoft.com/windows/win32/seccrypto/signer-cert
	internal const uint SIGNER_CERT_SPC_FILE = 0x01;
	internal const uint SIGNER_CERT_STORE = 0x02;
	internal const uint SIGNER_CERT_SPC_CHAIN = 0x03;

	// https://learn.microsoft.com/windows/win32/seccrypto/alg-id
	// Hash Algorithm Identifiers (ALG_ID)
	internal const uint CALG_SHA1 = 0x8004;
	internal const uint CALG_SHA_256 = 0x800c;
	internal const uint CALG_SHA_384 = 0x800d;
	internal const uint CALG_SHA_512 = 0x800e;

	internal const int S_OK = 0;
	internal const int ERROR_BAD_FORMAT_HRESULT = unchecked((int)0x8007000B);
	internal const int ERROR_FILE_NOT_FOUND_HRESULT = unchecked((int)0x80070002);
	internal const int E_INVALIDARG_HRESULT = unchecked((int)0x80070057);

	#region Native AOT compatible IUnknown VTable definitions

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	internal delegate uint Release_Delegate(IntPtr pUnk);

	[StructLayout(LayoutKind.Sequential)]
	internal struct IUnknownVtbl
	{
		internal IntPtr QueryInterface;
		internal IntPtr AddRef;
		internal IntPtr Release;
	}

	#endregion

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/seccrypto/signer-file-info
	/// </summary>
	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_FILE_INFO
	{
		internal uint cbSize;
		internal IntPtr pwszFileName;
		internal IntPtr hFile;
	}

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/seccrypto/signer-blob-info
	/// </summary>
	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_BLOB_INFO
	{
		internal uint cbSize;
		internal IntPtr pGuidSubject;
		internal uint cbBlob;
		internal IntPtr pbBlob;
		internal IntPtr pwszDisplayName;
	}

	[StructLayout(LayoutKind.Explicit)]
	internal struct SIGNER_SUBJECT_INFO_UNION
	{
		[FieldOffset(0)]
		internal IntPtr pSignerFileInfo;

		[FieldOffset(0)]
		internal IntPtr pSignerBlobInfo;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_SUBJECT_INFO
	{
		internal uint cbSize;
		internal IntPtr pdwIndex;
		internal uint dwSubjectChoice;
		internal SIGNER_SUBJECT_INFO_UNION Info;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_ATTR_AUTHCODE
	{
		internal uint cbSize;
		[MarshalAs(UnmanagedType.Bool)]
		internal bool fCommercial;
		[MarshalAs(UnmanagedType.Bool)]
		internal bool fIndividual;
		internal IntPtr pwszName;
		internal IntPtr pwszInfo;
	}

	[StructLayout(LayoutKind.Explicit)]
	internal struct SIGNER_SIGNATURE_INFO_UNION
	{
		[FieldOffset(0)]
		internal IntPtr pAttrAuthcode;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_SIGNATURE_INFO
	{
		internal uint cbSize;
		internal uint algidHash;
		internal uint dwAttrChoice;
		internal SIGNER_SIGNATURE_INFO_UNION Attr;
		internal IntPtr psAuthenticated;
		internal IntPtr psUnauthenticated;
	}

	[StructLayout(LayoutKind.Explicit)]
	internal struct SIGNER_PROVIDER_INFO_UNION
	{
		[FieldOffset(0)]
		internal IntPtr pwszPvkFileName;

		[FieldOffset(0)]
		internal IntPtr pwszKeyContainer;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_PROVIDER_INFO
	{
		internal uint cbSize;
		internal IntPtr pwszProviderName;
		internal uint dwProviderType;
		internal uint dwKeySpec;
		internal uint dwPvkChoice;
		internal SIGNER_PROVIDER_INFO_UNION PvkChoice;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_SPC_CHAIN_INFO
	{
		internal uint cbSize;
		internal IntPtr pwszSpcFile;
		internal uint dwCertPolicy;
		internal IntPtr hCertStore;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_CERT_STORE_INFO
	{
		internal uint cbSize;
		internal IntPtr pSigningCert;
		internal uint dwCertPolicy;
		internal IntPtr hCertStore;
	}

	[StructLayout(LayoutKind.Explicit)]
	internal struct SIGNER_CERT_UNION
	{
		[FieldOffset(0)]
		internal IntPtr pwszSpcFile;

		[FieldOffset(0)]
		internal IntPtr pCertStoreInfo;

		[FieldOffset(0)]
		internal IntPtr pSpcChainInfo;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_CERT
	{
		internal uint cbSize;
		internal uint dwCertChoice;
		internal SIGNER_CERT_UNION CertChoice;
		internal IntPtr hwnd;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_CONTEXT
	{
		internal uint cbSize;
		internal uint cbBlob;
		internal IntPtr pbBlob;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SIGNER_SIGN_EX3_PARAMS
	{
		internal uint dwFlags;
		internal IntPtr pSubjectInfo;
		internal IntPtr pSigningCert;
		internal IntPtr pSignatureInfo;
		internal IntPtr pProviderInfo;
		internal uint dwTimestampFlags;
		internal IntPtr pszAlgorithmOid;
		internal IntPtr pwszTimestampURL;
		internal IntPtr pCryptAttrs;
		internal IntPtr pSipData;
		internal IntPtr pSignerContext;
		internal IntPtr pCryptoPolicy;
		internal IntPtr pReserved;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct APPX_SIP_CLIENT_DATA
	{
		internal IntPtr pSignerParams;
		internal IntPtr pAppxSipState;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_ATTR_BLOB
	{
		internal uint cbData;
		internal IntPtr pbData;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_ATTRIBUTE
	{
		internal IntPtr pszObjId;
		internal uint cValue;
		internal IntPtr rgValue; // PCRYPT_ATTR_BLOB
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_ATTRIBUTES
	{
		internal uint cAttr;
		internal IntPtr rgAttr; // PCRYPT_ATTRIBUTE
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_SIGN_MESSAGE_PARA
	{
		internal uint cbSize;
		internal uint dwMsgEncodingType;
		internal IntPtr pSigningCert;
		internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm; // pszObjId will be a hash OID
		internal IntPtr pvHashAuxInfo;
		internal uint cMsgCert;
		internal IntPtr rgpMsgCert;
		internal uint cMsgCrl;
		internal IntPtr rgpMsgCrl;
		internal uint cAuthAttr;
		internal IntPtr rgAuthAttr;
		internal uint cUnauthAttr;
		internal IntPtr rgUnauthAttr;
		internal uint dwFlags;
		internal uint dwInnerContentType;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_ALGORITHM_IDENTIFIER
	{
		internal IntPtr pszObjId;
		internal CRYPT_OBJID_BLOB Parameters;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CRYPT_OBJID_BLOB
	{
		internal uint cbData;
		internal IntPtr pbData;
	}

	/// <summary>
	/// for page hashing support.
	/// https://learn.microsoft.com/windows/win32/seccrypto/signersignex3#parameters
	/// </summary>
	internal const uint SPC_INC_PE_PAGE_HASHES_FLAG = 0x00000100;

	internal static readonly Guid FLAT_SIP_GUID = new("C689AAB8-8E78-11D0-8C47-00C04C324A2E");

	/// <summary>
	/// We're signing special data for Code Integrity policy and it needs the following OID present in its signature.
	/// </summary>
	internal const string CodeIntegrityOID = "1.3.6.1.4.1.311.79.1";

	/// <summary>
	/// Code Signing OID.
	/// </summary>
	internal const string CodeSigningOID = "1.3.6.1.5.5.7.3.3";
}
