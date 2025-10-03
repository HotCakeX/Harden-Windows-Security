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
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace AppControlManager.Others;

/// <summary>
/// For retrieving Opus data from signed files
/// </summary>
internal static partial class Opus
{

	/// <summary>
	/// More info about this at the end of the code
	/// </summary>
	private const nint SPC_SP_OPUS_INFO_STRUCT = 2007;

	/// <summary>
	/// for the SpcSpOpusInfo structure
	/// </summary>
	private const string SPC_SP_OPUS_INFO_OBJID = "1.3.6.1.4.1.311.2.1.12";

	// Returns a List of OpusInfoObj, taking a SignedCms parameter
	// https://learn.microsoft.com/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
	// https://view.officeapps.live.com/op/view.aspx?src=https%3A%2F%2Fdownload.microsoft.com%2Fdownload%2F9%2Fc%2F5%2F9c5b2167-8017-4bae-9fde-d599bac8184a%2FAuthenticode_PE.docx
	internal unsafe static List<OpusInfoObj> GetOpusData(SignedCms signature)
	{
		// Initializing a new List of OpusInfoObj to store the output data to return
		List<OpusInfoObj> OEMOpusData = [];

		// Iterating through each SignerInfo in the SignerInfos collection of the signature
		foreach (SignerInfo signerInfo in signature.SignerInfos)
		{
			// Iterating through each CryptographicAttributeObject in the SignedAttributes collection of the signerInfo
			foreach (CryptographicAttributeObject signedAttribute in signerInfo.SignedAttributes)
			{
				// Checking if the OID value of the signed attribute matches the Opus SPC_SP_OPUS_INFO_OBJID
				if (string.Equals(signedAttribute.Oid.Value, SPC_SP_OPUS_INFO_OBJID, StringComparison.OrdinalIgnoreCase))
				{
					// Initializing pcbStructInfo to 0
					uint pcbStructInfo = 0;
					// Initializing decodedDataPtr to IntPtr.Zero
					IntPtr decodedDataPtr = IntPtr.Zero;

					try
					{
						AsnEncodedData asnEncodedData = signedAttribute.Values[0];  // Retrieving the first value from the signed attribute's Values collection

						// Decoding ASN.1-encoded data using CryptDecodeObject (1st pass to get size)
						if (!NativeMethods.CryptDecodeObject(65537U, SPC_SP_OPUS_INFO_STRUCT, asnEncodedData.RawData, (uint)asnEncodedData.RawData.Length, 0U, IntPtr.Zero, ref pcbStructInfo))
						{
							// If CryptDecodeObject fails, ignore
						}
						else
						{
							// Allocating unmanaged memory to decodedDataPtr based on pcbStructInfo size
							decodedDataPtr = Marshal.AllocCoTaskMem((int)pcbStructInfo);

							// Decoding ASN.1-encoded data again into decodedDataPtr (2nd pass actual decode)
							if (!NativeMethods.CryptDecodeObject(65537U, SPC_SP_OPUS_INFO_STRUCT, asnEncodedData.RawData, (uint)asnEncodedData.RawData.Length, 0U, decodedDataPtr, ref pcbStructInfo))
							{
								// If CryptDecodeObject fails, ignore
							}
							else
							{
								// Manually parsing the unmanaged SPC_SP_OPUS_INFO equivalent
								// Expected Layout (sequential pointers):
								// offset 0 * IntPtr.Size : LPCWSTR (CertOemID / publisher display)
								// offset 1 * IntPtr.Size : PublisherInfo (pointer to nested structure or string)
								// offset 2 * IntPtr.Size : MoreInfo (pointer to nested structure or string)
								IntPtr certOemIdPtr = Marshal.ReadIntPtr(decodedDataPtr, 0);
								IntPtr publisherInfoPtr = Marshal.ReadIntPtr(decodedDataPtr, IntPtr.Size);
								IntPtr moreInfoPtr = Marshal.ReadIntPtr(decodedDataPtr, 2 * IntPtr.Size);

								// Convert first pointer (if non-null) to managed string (Unicode)
								string certOemId = certOemIdPtr != IntPtr.Zero ? (Marshal.PtrToStringUni(certOemIdPtr) ?? string.Empty) : string.Empty;

								// Construct managed OpusInfoObj (fields are internal, so assigning directly)
								OpusInfoObj structure = new()
								{
									CertOemID = certOemId,
									PublisherInfo = publisherInfoPtr,
									MoreInfo = moreInfoPtr
								};

								// Adding the structure to OEMOpusData list
								OEMOpusData.Add(structure);
							}
						}
					}
					finally
					{
						// Freeing the allocated unmanaged memory
						Marshal.FreeCoTaskMem(decodedDataPtr);
					}
				}
			}
		}
		return OEMOpusData;
	}
}

// Constants

// WINTRUST_MAX_HEADER_BYTES_TO_MAP_DEFAULT = $00A00000
// WINTRUST_MAX_HASH_BYTES_TO_MAP_DEFAULT = $00100000
// WTD_UI_ALL = 1
// WTD_UI_NONE = 2
// WTD_UI_NOBAD = 3
// WTD_UI_NOGOOD = 4
// WTD_REVOKE_NONE = $00000000
// WTD_REVOKE_WHOLECHAIN = $00000001
// WTD_CHOICE_FILE = 1
// WTD_CHOICE_CATALOG = 2
// WTD_CHOICE_BLOB = 3
// WTD_CHOICE_SIGNER = 4
// WTD_CHOICE_CERT = 5
// WTD_STATEACTION_IGNORE = $00000000
// WTD_STATEACTION_VERIFY = $00000001
// WTD_STATEACTION_CLOSE = $00000002
// WTD_STATEACTION_AUTO_CACHE = $00000003
// WTD_STATEACTION_AUTO_CACHE_FLUSH = $00000004
// WTD_PROV_FLAGS_MASK = $0000FFFF
// WTD_USE_IE4_TRUST_FLAG = $00000001
// WTD_NO_IE4_CHAIN_FLAG = $00000002
// WTD_NO_POLICY_USAGE_FLAG = $00000004
// WTD_REVOCATION_CHECK_NONE = $00000010
// WTD_REVOCATION_CHECK_END_CERT = $00000020
// WTD_REVOCATION_CHECK_CHAIN = $00000040
// WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $00000080
// WTD_SAFER_FLAG = $00000100
// WTD_HASH_ONLY_FLAG = $00000200
// WTD_USE_DEFAULT_OSVER_CHECK = $00000400
// WTD_LIFETIME_SIGNING_FLAG = $00000800
// WTD_CACHE_ONLY_URL_RETRIEVAL = $00001000
// WTD_UICONTEXT_EXECUTE = 0
// WTD_UICONTEXT_INSTALL = 1
// WTCI_DONT_OPEN_STORES = $00000001
// WTCI_OPEN_ONLY_ROOT = $00000002
// WTCI_USE_LOCAL_MACHINE = $00000004
// WTPF_TRUSTTEST = $00000020
// WTPF_TESTCANBEVALID = $00000080
// WTPF_IGNOREEXPIRATION = $00000100
// WTPF_IGNOREREVOKATION = $00000200
// WTPF_OFFLINEOK_IND = $00000400
// WTPF_OFFLINEOK_COM = $00000800
// WTPF_OFFLINEOKNBU_IND = $00001000
// WTPF_OFFLINEOKNBU_COM = $00002000
// WTPF_VERIFY_V1_OFF = $00010000
// WTPF_IGNOREREVOCATIONONTS = $00020000
// WTPF_ALLOWONLYPERTRUST = $00040000
// TRUSTERROR_STEP_WVTPARAMS = 0
// TRUSTERROR_STEP_FILEIO = 2
// TRUSTERROR_STEP_SIP = 3
// TRUSTERROR_STEP_SIPSUBJINFO = 5
// TRUSTERROR_STEP_CATALOGFILE = 6
// TRUSTERROR_STEP_CERTSTORE = 7
// TRUSTERROR_STEP_MESSAGE = 8
// TRUSTERROR_STEP_MSG_SIGNERCOUNT = 9
// TRUSTERROR_STEP_MSG_INNERCNTTYPE = 10
// TRUSTERROR_STEP_MSG_INNERCNT = 11
// TRUSTERROR_STEP_MSG_STORE = 12
// TRUSTERROR_STEP_MSG_SIGNERINFO = 13
// TRUSTERROR_STEP_MSG_SIGNERCERT = 14
// TRUSTERROR_STEP_MSG_CERTCHAIN = 15
// TRUSTERROR_STEP_MSG_COUNTERSIGINFO = 16
// TRUSTERROR_STEP_MSG_COUNTERSIGCERT = 17
// TRUSTERROR_STEP_VERIFY_MSGHASH = 18
// TRUSTERROR_STEP_VERIFY_MSGINDIRECTDATA = 19
// TRUSTERROR_STEP_FINAL_WVTINIT = 30
// TRUSTERROR_STEP_FINAL_INITPROV = 31
// TRUSTERROR_STEP_FINAL_OBJPROV = 32
// TRUSTERROR_STEP_FINAL_SIGPROV = 33
// TRUSTERROR_STEP_FINAL_CERTPROV = 34
// TRUSTERROR_STEP_FINAL_CERTCHKPROV = 35
// TRUSTERROR_STEP_FINAL_POLICYPROV = 36
// TRUSTERROR_STEP_FINAL_UIPROV = 37
// TRUSTERROR_MAX_STEPS = 38
// CPD_USE_NT5_CHAIN_FLAG = $80000000
// CPD_REVOCATION_CHECK_NONE = $00010000
// CPD_REVOCATION_CHECK_END_CERT = $00020000
// CPD_REVOCATION_CHECK_CHAIN = $00040000
// CPD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $00080000
// CPD_UISTATE_MODE_PROMPT = $00000000
// CPD_UISTATE_MODE_BLOCK = $00000001
// CPD_UISTATE_MODE_ALLOW = $00000002
// CPD_UISTATE_MODE_MASK = $00000003
// CERT_CONFIDENCE_SIG = $10000000
// CERT_CONFIDENCE_TIME = $01000000
// CERT_CONFIDENCE_TIMENEST = $00100000
// CERT_CONFIDENCE_AUTHIDEXT = $00010000
// CERT_CONFIDENCE_HYGIENE = $00001000
// CERT_CONFIDENCE_HIGHEST = $11111000
// DWACTION_ALLOCANDFILL = 1
// DWACTION_FREE = 2
// szOID_TRUSTED_CODESIGNING_CA_LIST = "1.3.6.1.4.1.311.2.2.1"
// szOID_TRUSTED_CLIENT_AUTH_CA_LIST = "1.3.6.1.4.1.311.2.2.2"
// szOID_TRUSTED_SERVER_AUTH_CA_LIST = "1.3.6.1.4.1.311.2.2.3"
// SPC_TIME_STAMP_REQUEST_OBJID = "1.3.6.1.4.1.311.3.2.1"
// SPC_INDIRECT_DATA_OBJID = "1.3.6.1.4.1.311.2.1.4"
// SPC_SP_AGENCY_INFO_OBJID = "1.3.6.1.4.1.311.2.1.10"
// SPC_STATEMENT_TYPE_OBJID = "1.3.6.1.4.1.311.2.1.11"
// SPC_SP_OPUS_INFO_OBJID = "1.3.6.1.4.1.311.2.1.12"
// SPC_CERT_EXTENSIONS_OBJID = "1.3.6.1.4.1.311.2.1.14"
// SPC_PE_IMAGE_DATA_OBJID = "1.3.6.1.4.1.311.2.1.15"
// SPC_RAW_FILE_DATA_OBJID = "1.3.6.1.4.1.311.2.1.18"
// SPC_STRUCTURED_STORAGE_DATA_OBJID = "1.3.6.1.4.1.311.2.1.19"
// SPC_JAVA_CLASS_DATA_OBJID = "1.3.6.1.4.1.311.2.1.20"
// SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.21"
// SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.22"
// SPC_CAB_DATA_OBJID = "1.3.6.1.4.1.311.2.1.25"
// SPC_GLUE_RDN_OBJID = "1.3.6.1.4.1.311.2.1.25"
// SPC_MINIMAL_CRITERIA_OBJID = "1.3.6.1.4.1.311.2.1.26"
// SPC_FINANCIAL_CRITERIA_OBJID = "1.3.6.1.4.1.311.2.1.27"
// SPC_LINK_OBJID = "1.3.6.1.4.1.311.2.1.28"
// SPC_SIGINFO_OBJID = "1.3.6.1.4.1.311.2.1.30"
// SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID = "1.3.6.1.4.1.311.2.3.1"
// SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID = "1.3.6.1.4.1.311.2.3.2"
// CAT_NAMEVALUE_OBJID = "1.3.6.1.4.1.311.12.2.1"
// CAT_MEMBERINFO_OBJID = "1.3.6.1.4.1.311.12.2.2"
// SPC_SP_AGENCY_INFO_STRUCT =(2000)
// SPC_MINIMAL_CRITERIA_STRUCT =(2001)
// SPC_FINANCIAL_CRITERIA_STRUCT =(2002)
// SPC_INDIRECT_DATA_CONTENT_STRUCT =(2003)
// SPC_PE_IMAGE_DATA_STRUCT =(2004)
// SPC_LINK_STRUCT =(2005)
// SPC_STATEMENT_TYPE_STRUCT =(2006)
// SPC_SP_OPUS_INFO_STRUCT =(2007)
// SPC_CAB_DATA_STRUCT =(2008)
// SPC_JAVA_CLASS_DATA_STRUCT =(2009)
// SPC_SIGINFO_STRUCT =(2130)
// CAT_NAMEVALUE_STRUCT =(2221)
// CAT_MEMBERINFO_STRUCT =(2222)
// SPC_UUID_LENGTH = 16
// WIN_CERT_REVISION_1_0 =($0100)
// WIN_CERT_REVISION_2_0 =($0200)
// WIN_CERT_TYPE_X509 =($0001)
// WIN_CERT_TYPE_PKCS_SIGNED_DATA =($0002)
// WIN_CERT_TYPE_RESERVED_1 =($0003)
// WIN_CERT_TYPE_TS_STACK_SIGNED =($0004)
// WT_TRUSTDBDIALOG_NO_UI_FLAG = $00000001
// WT_TRUSTDBDIALOG_ONLY_PUB_TAB_FLAG = $00000002
// WT_TRUSTDBDIALOG_WRITE_LEGACY_REG_FLAG = $00000100
// WT_TRUSTDBDIALOG_WRITE_IEAK_STORE_FLAG = $00000200
