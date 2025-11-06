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

using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Vyre;

/// <summary>
/// Immutable in‑memory representation of a single CTL "trusted subject" entry
/// (an item in the TrustedSubjects sequence of the AuthRoot Certificate Trust List).
/// The CTL does NOT embed the full certificate – it embeds identifiers / metadata
/// (hashes, key usages, gating dates, etc.)
/// </summary>
internal sealed class SubjectEntry(
	string friendlyName,
	string sha256Fingerprint,
	string sha1Fingerprint,
	string subjectNameMD5,
	string keyID,
	List<string> extendedKeyUsage,
	DateTime? disabledDate,
	DateTime? notBefore,
	List<string> notBeforeEKU)
{
	/// <summary>
	/// OID: 1.3.6.1.4.1.311.10.11.11 (value stored as UTF-16LE, NUL-terminated).
	/// </summary>
	internal string FriendlyName => friendlyName;

	/// <summary>
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.98 (raw 32-byte digest in the CTL).
	/// </summary>
	internal string SHA256Fingerprint => sha256Fingerprint;

	/// <summary>
	/// Uppercase hexadecimal SHA-1 fingerprint sourced from the CTL's SubjectIdentifier OCTET STRING
	/// Not taken from a separate attribute.
	/// </summary>
	internal string SHA1Fingerprint => sha1Fingerprint;

	/// <summary>
	/// Uppercase hexadecimal MD5 hash of the canonicalized subject name (NOT a hash of the full certificate).
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.29.
	/// </summary>
	internal string SubjectNameMD5 => subjectNameMD5;

	/// <summary>
	/// Uppercase hexadecimal key identifier (often parallels the certificate's Subject Key Identifier extension).
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.20.
	/// </summary>
	internal string KeyID => keyID;

	/// <summary>
	/// EKU OIDs that apply to this subject (unconditional list).
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.9 (DER SEQUENCE of OBJECT IDENTIFIERs).
	/// May be empty if no special EKU constraints are declared.
	/// </summary>
	internal List<string> ExtendedKeyUsage => extendedKeyUsage;

	/// <summary>
	/// UTC date (FILETIME converted) when Microsoft disabled/distrusted this subject.
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.104.
	/// Null if the subject has not been explicitly disabled.
	/// </summary>
	internal DateTime? DisabledDate => disabledDate;

	/// <summary>
	/// UTC earliest usage gating date (FILETIME) for this subject within the root program context.
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.126.
	/// Null if no gating (earliest usage) constraint is specified.
	/// </summary>
	internal DateTime? NotBefore => notBefore;

	/// <summary>
	/// Attribute OID: 1.3.6.1.4.1.311.10.11.127 (DER SEQUENCE of OBJECT IDENTIFIERs).
	/// Empty if no conditional EKU gating is defined.
	/// </summary>
	internal List<string> NotBeforeEKU => notBeforeEKU;
}

/// <summary>
/// Immutable CTL header metadata extracted from the SignedCms content payload.
/// </summary>
internal sealed class CtlHeader(
	int version,
	string usageOid,
	string usageFriendlyName,
	string? sequenceNumberHexLower,
	DateTime thisUpdateUtc,
	DateTime? nextUpdateUtc,
	string algorithmOid,
	string algorithmOidFriendlyName,
	ReadOnlyMemory<byte> digestAlgorithmParameters,
	int entryCount)
{
	/// <summary>
	/// CTL version INTEGER (observed values 0 or 1 in AuthRoot lists).
	/// </summary>
	internal int Version => version;

	/// <summary>
	/// Usage OBJECT IDENTIFIER (e.g., 1.3.6.1.4.1.311.10.3.9 for "Root List Signer").
	/// Determines the semantic purpose of this CTL.
	/// </summary>
	internal string UsageOid => usageOid;

	/// <summary>
	/// Friendly name mapped from the usage OID (if a known mapping exists; otherwise empty string).
	/// </summary>
	internal string UsageFriendlyName => usageFriendlyName;

	/// <summary>
	/// Optional monotonic sequence number of the CTL encoded as a lowercase hexadecimal string.
	/// Null if the CTL omitted the SequenceNumber INTEGER.
	/// </summary>
	internal string? SequenceNumberHexLower => sequenceNumberHexLower;

	/// <summary>
	/// UTC time (ThisUpdate) indicating when this CTL was generated / became effective.
	/// Must fall within the signing certificate's validity window.
	/// </summary>
	internal DateTime ThisUpdateUtc => thisUpdateUtc;

	/// <summary>
	/// Optional UTC time (NextUpdate) suggesting when a subsequent CTL might appear.
	/// Null if the CTL does not advertise a next update.
	/// </summary>
	internal DateTime? NextUpdateUtc => nextUpdateUtc;

	/// <summary>
	/// AlgorithmIdentifier.OBJECT IDENTIFIER specifying the hash algorithm applied to subject identifiers
	/// (e.g., 1.3.14.3.2.26 for SHA-1, 2.16.840.1.101.3.4.2.1 for SHA-256).
	/// </summary>
	internal string AlgorithmOid => algorithmOid;

	/// <summary>
	/// Friendly label for the algorithm OID (if recognized; otherwise empty string).
	/// </summary>
	internal string AlgorithmOidFriendlyName => algorithmOidFriendlyName;

	/// <summary>
	/// Raw encoded AlgorithmIdentifier parameters (often NULL 05 00 or absent).
	/// Empty when no parameters are present.
	/// </summary>
	internal ReadOnlyMemory<byte> DigestAlgorithmParameters => digestAlgorithmParameters;

	/// <summary>
	/// Number of TrustedSubject entries parsed from the CTL.
	/// </summary>
	internal int EntryCount => entryCount;
}

/// <summary>
/// Aggregate parse result: header + the list of Subject entries.
/// </summary>
internal sealed class TrustListParseResult(CtlHeader header, List<SubjectEntry> subjects)
{
	internal CtlHeader Header => header;
	internal List<SubjectEntry> Subjects => subjects;
}

/// <summary>
/// Model for a certificate that does NOT chain to any STL root.
/// </summary>
internal sealed class NonStlRootCert(
	string storeLocationString,
	string storeNameString,
	string subject,
	string issuer,
	string leafThumbprintSha1,
	string rootSubject,
	string rootSha256Hex)
{
	[JsonInclude]
	[JsonPropertyName("Store Location")]
	internal string StoreLocationString => storeLocationString;

	[JsonInclude]
	[JsonPropertyName("Store Name")]
	internal string StoreNameString => storeNameString;

	[JsonInclude]
	[JsonPropertyName("Subject")]
	internal string Subject => subject;

	[JsonInclude]
	[JsonPropertyName("Issuer")]
	internal string Issuer => issuer;

	[JsonInclude]
	[JsonPropertyName("Leaf Certificate Thumbprint - SHA1")]
	internal string LeafThumbprintSha1 => leafThumbprintSha1;

	[JsonInclude]
	[JsonPropertyName("Root Certificate Subject")]
	internal string RootSubject => rootSubject;

	[JsonInclude]
	[JsonPropertyName("Root Certificate SHA256 Hash")]
	internal string RootSha256Hex => rootSha256Hex;
}

/// <summary>
/// JSON source generation context for <see cref="NonStlRootCert"/> serialization
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(NonStlRootCert))]
[JsonSerializable(typeof(List<NonStlRootCert>))]
internal sealed partial class NonStlRootCertJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Unified processor for AuthRoot files, supporting both CAB extraction and STL parsing.
/// </summary>
internal static class AuthRootProcessor
{
	// PKCS#7 / CMS AuthRoot CTL content type OID (must match ContentInfo in SignedCms)
	private const string OidCtl = "1.3.6.1.4.1.311.10.1";

	// Attribute / extension OIDs used within individual TrustedSubject entries.
	private const string OidFriendlyName = "1.3.6.1.4.1.311.10.11.11";
	private const string OidKeyId = "1.3.6.1.4.1.311.10.11.20";
	private const string OidSubjectNameMd5 = "1.3.6.1.4.1.311.10.11.29";
	private const string OidSha256Fingerprint = "1.3.6.1.4.1.311.10.11.98";
	private const string OidEku = "1.3.6.1.4.1.311.10.11.9";
	private const string OidNotBeforeEku = "1.3.6.1.4.1.311.10.11.127";
	private const string OidDisabledDate = "1.3.6.1.4.1.311.10.11.104";
	private const string OidNotBeforeDate = "1.3.6.1.4.1.311.10.11.126";

	// Known CTL Usage OIDs (maps to a friendly display name). AuthRoot typically uses 1.3.6.1.4.1.311.10.3.9.
	private static readonly Dictionary<string, string> UsageFriendlyNames = new(StringComparer.OrdinalIgnoreCase)
	{
		{ "1.3.6.1.4.1.311.10.3.9", "Root List Signer" }
	};

	// Simple digest / algorithm OID human-readable mapping for clarity in output.
	private static readonly Dictionary<string, string> AlgorithmFriendlyNames = new(StringComparer.OrdinalIgnoreCase)
	{
		{ "1.3.14.3.2.26", "sha1 (sha1NoSign)" },
		{ "2.16.840.1.101.3.4.2.1", "sha256" }
	};

	/// <summary>
	/// Known certificate store names from registry discovery, the <see cref="StoreLocation"/> enum wouldn't have all of these store names.
	/// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates
	/// </summary>
	internal static readonly string[] knownStoreNames =
	[
		"AAD Token Issuer",
		"AddressBook",
		"AuthRoot",
		"CA",
		"ClientAuthIssuer",
		"Disallowed",
		"eSIM Certification Authorities",
		"FlightRoot",
		"MY",
		"OemEsim",
		"PasspointTrustedRoots",
		"REQUEST",
		"ROOT",
		"Shielded VM Local Certificates",
		"SmartCardRoot",
		"TestSignRoot",
		"trust",
		"TrustedAppRoot",
		"TrustedDevices",
		"TrustedPeople",
		"TrustedPublisher",
		"Windows Live ID Token Issuer",
		"WindowsServerUpdateServices"
	];


	internal static readonly StoreLocation[] storeLocations =
	[
		StoreLocation.CurrentUser,
		StoreLocation.LocalMachine
	];

	/// <summary>
	/// Main orchestrator method that processes either CAB or STL files from local paths or URLs.
	/// Automatically detects file type and handles CAB extraction in memory if needed.
	/// Returns both CTL header and subjects list.
	/// </summary>
	/// <param name="filePathOrUrl">Local file path or HTTP/HTTPS URL to CAB or STL file</param>
	/// <param name="caCertificatePathOrUrl">Local file path or HTTP/HTTPS URL to CA certificate for validation</param>
	/// <returns>Complete parse result with CTL header and subjects list</returns>
	internal static TrustListParseResult ProcessAuthRoot(string filePathOrUrl, string caCertificatePathOrUrl)
	{
		// Load the input file (CAB or STL) into memory
		byte[] inputFileBytes = LoadFile(filePathOrUrl);

		// Load the CA certificate for validation
		X509Certificate2 caCert = LoadCertificateFromPathOrUrl(caCertificatePathOrUrl);

		// Determine if the input is a CAB or STL file and process accordingly
		byte[] stlBytes = DetermineFileTypeAndExtract(inputFileBytes);

		// Parse the STL content and return the result
		return ParseSignedCmsAndCtl(stlBytes, caCert);
	}

	/// <summary>
	/// Determines whether the input bytes represent a CAB or STL file and extracts accordingly.
	/// For CAB files: extracts the single STL file contained within in memory.
	/// For STL files: returns the bytes as-is.
	/// </summary>
	/// <param name="inputBytes">Raw file bytes</param>
	/// <returns>STL file bytes ready for parsing</returns>
	private static byte[] DetermineFileTypeAndExtract(byte[] inputBytes)
	{
		// Check for CAB file signature: "MSCF" at the beginning
		if (inputBytes.Length >= 4 &&
			inputBytes[0] == 0x4D && inputBytes[1] == 0x53 &&
			inputBytes[2] == 0x43 && inputBytes[3] == 0x46)
		{
			// This is a CAB file, extract the STL from it in memory
			return ExtractStlFromCabInMemory(inputBytes);
		}

		// Check for PKCS#7 signature (STL files start with DER-encoded SignedData)
		if (inputBytes.Length >= 2 && inputBytes[0] == 0x30)
		{
			// This appears to be an STL file (DER-encoded), return as-is
			return inputBytes;
		}

		throw new InvalidDataException(GlobalVars.GetStr("InputFileIsNeitherCABNorSTLError"));
	}

	/// <summary>
	/// Extracts the single STL file from a CAB archive in memory without writing any files to disk.
	/// The CAB file is expected to contain exactly one STL file.
	/// </summary>
	/// <param name="cabBytes">CAB file bytes</param>
	/// <returns>Extracted STL file bytes</returns>
	private static byte[] ExtractStlFromCabInMemory(byte[] cabBytes)
	{
		byte[]? extractedStlBytes = null;
		int extractedFileCount = 0;

		// Extract files in memory
		using (CabinetArchiveExtractor.CabinetDecompressionContext decompressionContext = new(cabBytes, cabinetEntry =>
		{
			// We expect only one file in the CAB (the STL file)
			extractedFileCount++;

			if (extractedFileCount > 1)
			{
				throw new InvalidDataException(GlobalVars.GetStr("CABFileContainsMoreThanOneFileError"));
			}

			// Check if this looks like an STL file by checking the file extension or content
			if (cabinetEntry.Name.EndsWith(".stl", StringComparison.OrdinalIgnoreCase) ||
				(cabinetEntry.Data.Length > 2 && cabinetEntry.Data.Span[0] == 0x30))
			{
				extractedStlBytes = cabinetEntry.Data.ToArray();
			}
			else
			{
				throw new InvalidDataException($"Extracted file '{cabinetEntry.Name}' does not appear to be an STL file.");
			}
		}))
		{
			decompressionContext.Run();
		}

		if (extractedStlBytes == null)
		{
			throw new InvalidDataException(GlobalVars.GetStr("NoSTLFileFoundInCABError"));
		}

		if (extractedFileCount == 0)
		{
			throw new InvalidDataException(GlobalVars.GetStr("CABFileEmptyError"));
		}

		return extractedStlBytes;
	}

	/// <summary>
	/// Loads a file from either a local path or URL.
	/// Supports HTTP and HTTPS URLs for downloading files.
	/// </summary>
	/// <param name="pathOrUrl">Local file path or HTTP/HTTPS URL</param>
	/// <returns>File bytes</returns>
	private static byte[] LoadFile(string pathOrUrl)
	{
		if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
			pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
		{
			using SocketsHttpHandler handler = new()
			{
				AllowAutoRedirect = false
			};

			using HttpClient httpClient = new(handler);
			Uri currentUri = new(pathOrUrl);
			const int maxRedirects = 15;

			for (int i = 0; i < maxRedirects; i++)
			{
				using HttpRequestMessage request = new(HttpMethod.Get, currentUri);
				using HttpResponseMessage response = httpClient.Send(request, HttpCompletionOption.ResponseHeadersRead);

				if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
				{
					Uri? location = response.Headers.Location ?? throw new HttpRequestException(GlobalVars.GetStr("RedirectResponseMissingLocationError"));
					currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
					continue;
				}

				_ = response.EnsureSuccessStatusCode();
				return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
			}

			throw new HttpRequestException(GlobalVars.GetStr("TooManyRedirectsError"));
		}
		else
		{
			return File.ReadAllBytes(pathOrUrl);
		}
	}

	/// <summary>
	/// Loads a certificate from either a local path or URL.
	/// Supports both PEM and DER certificate formats.
	/// </summary>
	/// <param name="pathOrUrl">Local file path or HTTP/HTTPS URL to certificate</param>
	/// <returns>X509Certificate2 instance</returns>
	private static X509Certificate2 LoadCertificateFromPathOrUrl(string pathOrUrl)
	{
		byte[] certBytes = LoadFile(pathOrUrl);
		return LoadCertificateFromBytes(certBytes);
	}

	/// <summary>
	/// Loads a certificate from raw bytes, supporting both PEM and DER formats.
	/// For PEM files: manual strip & base64 decode.
	/// </summary>
	/// <param name="certBytes">Certificate bytes</param>
	/// <returns>X509Certificate2 instance</returns>
	private static X509Certificate2 LoadCertificateFromBytes(byte[] certBytes)
	{
		// Basic heuristic: ensure the file looks ASCII before searching for the PEM marker to avoid decoding binary DER.
		string text = DetectAscii(certBytes) ? Encoding.ASCII.GetString(certBytes) : string.Empty;
		if (!string.IsNullOrEmpty(text) &&
			text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.OrdinalIgnoreCase))
		{
			return X509CertificateLoader.LoadCertificate(ExtractPemBlock(certBytes));
		}
		return X509CertificateLoader.LoadCertificate(certBytes);
	}

	/// <summary>
	/// Primary entry point: decodes & verifies the SignedCms for the AuthRoot CTL file,
	/// validates the signer and time windows, and returns complete structured data.
	/// </summary>
	internal static TrustListParseResult ParseWithMetadata(string stlFilePath, string caCertificatePath)
	{
		// Load raw PKCS#7 (SignedCms) bytes and the CA certificate used to build a trust chain.
		byte[] stlData = File.ReadAllBytes(stlFilePath);
		X509Certificate2 caCert = LoadCertificate(caCertificatePath);

		return ParseSignedCmsAndCtl(stlData, caCert);
	}

	/// <summary>
	/// Internal orchestrator that:
	/// 1. Decodes SignedCms
	/// 2. Verifies the signature (content integrity)
	/// 3. Builds / validates the certificate chain of the signing cert against supplied CA
	/// 4. Parses the embedded CTL ASN.1 payload
	/// </summary>
	private static TrustListParseResult ParseSignedCmsAndCtl(byte[] stlData, X509Certificate2 caCertificate)
	{
		SignedCms signedCms = new();

		// Decode the PKCS#7 Signed Data object.
		signedCms.Decode(stlData);

		// Verify the embedded content type matches the Microsoft CTL OID.
		string contentTypeOid = signedCms.ContentInfo.ContentType.Value ?? string.Empty;
		if (!string.Equals(contentTypeOid, OidCtl, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidDataException("Unexpected ContentInfo content type OID '" + contentTypeOid + "', expected '" + OidCtl + "'.");
		}

		// Validate the CMS signature (ensures content integrity before deeper ASN.1 parsing).
		try
		{
			signedCms.CheckSignature(true);
		}
		catch (CryptographicException ex)
		{
			throw new CryptographicException(GlobalVars.GetStr("SignatureVerificationFailedError"), ex);
		}

		// AuthRoot CTL releases have exactly one signer.
		if (signedCms.SignerInfos.Count != 1)
		{
			throw new InvalidDataException("Expected exactly one signer info, found " + signedCms.SignerInfos.Count + ".");
		}

		SignerInfo signer = signedCms.SignerInfos[0];
		X509Certificate2 signingCert = signer.Certificate ?? throw new InvalidDataException(GlobalVars.GetStr("SignerCertificateNotPresentError"));

		// Build a chain rooted in the provided CA certificate to validate the signer.
		ValidateSignerChain(signingCert, signedCms.Certificates, caCertificate);

		// Pass the DER payload of the CTL to the lower-level parser.
		ReadOnlyMemory<byte> ctlContent = signedCms.ContentInfo.Content;
		TrustListParseResult result = DecodeCtlContent(ctlContent, signingCert);
		return result;
	}

	/// <summary>
	/// Builds and validates the X509 chain for the signing certificate against a provided root CA.
	/// CustomRootTrust mode ensures ONLY the specified CA is treated as trust anchor. This way we don't base our trust on the current system.
	/// Uses a verification time near end-of-validity (minus 1 day) replicating the approach where CTLs can be published near cert expiry.
	/// </summary>
	private static void ValidateSignerChain(X509Certificate2 signingCert, X509Certificate2Collection embeddedCerts, X509Certificate2 caCert)
	{
		using X509Chain chain = new()
		{
			ChainPolicy =
			{
				RevocationMode = X509RevocationMode.NoCheck,
				RevocationFlag = X509RevocationFlag.ExcludeRoot,
				VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid   // We manually time-scope below.
			}
		};

		// Restrict trust to the provided CA (Root Pinning so we don't trust the certificates available on the same system we are trying to verify).
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		_ = chain.ChainPolicy.CustomTrustStore.Add(caCert);

		// Add intermediates (except the leaf) to ExtraStore so the builder can chain fully.
		for (int i = 0; i < embeddedCerts.Count; i++)
		{
			X509Certificate2 candidate = embeddedCerts[i];
			if (!candidate.Thumbprint.Equals(signingCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
			{
				_ = chain.ChainPolicy.ExtraStore.Add(candidate);
			}
		}

		// Verification time: one day before NotAfter (if still after NotBefore),
		// else midpoint of the cert validity window.
		DateTime verificationTime = signingCert.NotAfter.AddDays(-1);
		if (verificationTime <= signingCert.NotBefore)
		{
			TimeSpan validitySpan = signingCert.NotAfter - signingCert.NotBefore;
			TimeSpan halfSpan = validitySpan / 2;
			verificationTime = signingCert.NotBefore.Add(halfSpan);
		}
		chain.ChainPolicy.VerificationTime = verificationTime;

		bool ok = chain.Build(signingCert);
		if (!ok)
		{
			List<string> errors = [];
			for (int i = 0; i < chain.ChainStatus.Length; i++)
			{
				X509ChainStatus status = chain.ChainStatus[i];
				// Filter out NotTimeValid
				if (status.Status != X509ChainStatusFlags.NotTimeValid &&
					status.Status != X509ChainStatusFlags.NoError)
				{
					errors.Add(status.StatusInformation.Trim());
				}
			}
			if (errors.Count > 0)
			{
				throw new CryptographicException("Failed to build signing certificate chain: " + string.Join("; ", errors));
			}
		}

		// Ensure the built chain root equals the provided CA (enforces expected anchor).
		X509Certificate2? root = chain.ChainElements.Count > 0 ? chain.ChainElements[^1].Certificate : null;
		if (root == null ||
			!root.Thumbprint.Equals(caCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
		{
			throw new CryptographicException(GlobalVars.GetStr("SigningChainRootMismatchError"));
		}
	}

	/// <summary>
	/// Parses the DER-encoded CTL structure AFTER signature verification.
	/// Performs tag-by-tag validation.
	/// </summary>
	private static TrustListParseResult DecodeCtlContent(ReadOnlyMemory<byte> data, X509Certificate2 signingCert)
	{
		// Create top-level ASN.1 reader directly over original memory.
		AsnReader topReader = new(data, AsnEncodingRules.DER);
		AsnReader ctlSeq = topReader.ReadSequence();

		if (topReader.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("UnexpectedTrailingDataCTLError"));
		}

		// Local accumulators for immutable header construction.
		int versionLocal = 0;
		string? sequenceNumberHexLowerLocal = null;
		DateTime thisUpdateUtcLocal;
		DateTime? nextUpdateUtcLocal = null;
		ReadOnlyMemory<byte> algorithmParametersRawLocal = ReadOnlyMemory<byte>.Empty;

		// Version (optional) – only 0 or 1 accepted in real AuthRoot CTLs.
		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.Universal &&
			ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.Integer)
		{
			BigInteger versionBig = ctlSeq.ReadInteger();
			int versionParsed;
			try
			{
				versionParsed = checked((int)versionBig);
			}
			catch (OverflowException)
			{
				throw new InvalidDataException(GlobalVars.GetStr("VersionIntegerOutOfRangeError"));
			}
			if (versionParsed != 0 && versionParsed != 1)
			{
				throw new InvalidDataException("Unsupported CTL version: " + versionParsed.ToString(CultureInfo.InvariantCulture));
			}
			versionLocal = versionParsed;
		}

		// Usage: outer SEQUENCE containing the usage OBJECT IDENTIFIER (root list signer OID).
		if (!ctlSeq.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("MissingUsageSequenceError"));
		}
		AsnReader usageSequence = ctlSeq.ReadSequence();
		string usageOid = usageSequence.ReadObjectIdentifier();
		if (usageSequence.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("UnexpectedTrailingDataUsageSequenceError"));
		}
		string usageOidLocal = usageOid;
		string usageFriendlyNameLocal = UsageFriendlyNames.TryGetValue(usageOid, out string? uf) ? uf : string.Empty;

		// Optional listIdentifier BIT STRING.
		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.Universal &&
			ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.BitString)
		{
			_ = ctlSeq.ReadBitString(out _);
		}

		// Optional sequenceNumber – used to identify monotonic list iteration / versioning.
		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.Universal &&
			ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.Integer)
		{
			BigInteger seqNum = ctlSeq.ReadInteger();
			sequenceNumberHexLowerLocal = BigIntegerToLowerHex(seqNum);
		}

		// Mandatory ThisUpdate – generation time of the CTL.
		if (!ctlSeq.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("MissingThisUpdateError"));
		}
		DateTime thisUpdate = ParseAsnTime(ctlSeq);
		thisUpdateUtcLocal = thisUpdate;

		// Optional NextUpdate – indicates when a refresh might occur.
		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.Universal &&
			(ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.UtcTime ||
			 ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.GeneralizedTime))
		{
			DateTime nextUpdate = ParseAsnTime(ctlSeq);
			nextUpdateUtcLocal = nextUpdate;
		}

		// AlgorithmIdentifier
		if (!ctlSeq.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("MissingAlgorithmIdentifierError"));
		}
		AsnReader algSeq = ctlSeq.ReadSequence();
		string algOid = algSeq.ReadObjectIdentifier();
		string algorithmOidLocal = algOid;
		string algorithmOidFriendlyNameLocal = AlgorithmFriendlyNames.TryGetValue(algOid, out string? af) ? af : string.Empty;
		if (algSeq.HasData)
		{
			// Capture raw parameters exactly (often NULL or absent). Loop allows for any extraneous encoded values.
			using MemoryStream ms = new();
			while (algSeq.HasData)
			{
				ReadOnlyMemory<byte> enc = algSeq.ReadEncodedValue();
				ms.Write(enc.Span);
			}
			algorithmParametersRawLocal = ms.Length > 0 ? new ReadOnlyMemory<byte>(ms.ToArray()) : ReadOnlyMemory<byte>.Empty;
		}

		// Validate CTL temporal coherence relative to signer certificate validity.
		// This enforces that the CTL issuance (ThisUpdate) falls within the active range of the signing cert.
		if (thisUpdate < signingCert.NotBefore.ToUniversalTime())
		{
			throw new InvalidDataException("CTL thisUpdate '" + thisUpdate.ToString("o", CultureInfo.InvariantCulture) +
										   "' is before signing cert NotBefore '" + signingCert.NotBefore.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) + "'.");
		}
		if (thisUpdate > signingCert.NotAfter.ToUniversalTime())
		{
			throw new InvalidDataException("CTL thisUpdate '" + thisUpdate.ToString("o", CultureInfo.InvariantCulture) +
										   "' is after signing cert NotAfter '" + signingCert.NotAfter.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) + "'.");
		}

		// Parse zero or more subjects. Each describes a potential root (or other anchor) with associated policy.
		List<SubjectEntry> subjects = [];

		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.Universal &&
			ctlSeq.PeekTag().TagValue == (int)UniversalTagNumber.Sequence)
		{
			AsnReader trustedSubjectsSeq = ctlSeq.ReadSequence();
			while (trustedSubjectsSeq.HasData)
			{
				AsnReader trustedSubjectSeq = trustedSubjectsSeq.ReadSequence();

				// subjectIdentifier = SHA1 fingerprint (20 bytes) stored as OCTET STRING
				byte[] subjectIdentifier = trustedSubjectSeq.ReadOctetString();
				string sha1Fingerprint = Convert.ToHexString(subjectIdentifier);

				// Attributes: SET OF (each attr a SEQUENCE of OID + SET OF values)
				AsnReader attributesSet = trustedSubjectSeq.ReadSetOf();
				List<RawAttribute> rawAttributes = [];

				while (attributesSet.HasData)
				{
					AsnReader attrSeq = attributesSet.ReadSequence();
					string attrOid = attrSeq.ReadObjectIdentifier();

					AsnReader valuesSet = attrSeq.ReadSetOf();
					List<byte[]> values = [];
					while (valuesSet.HasData)
					{
						byte[] val = valuesSet.ReadOctetString();
						values.Add(val);
					}

					rawAttributes.Add(new RawAttribute(attrOid, values));
				}

				if (trustedSubjectSeq.HasData)
				{
					throw new InvalidDataException(GlobalVars.GetStr("UnexpectedTrailingDataTrustedSubjectError"));
				}

				// Convert raw attribute bag into structured Subject with validation.
				SubjectEntry subject = MaterializeSubjectEntry(sha1Fingerprint, rawAttributes);
				subjects.Add(subject);
			}
		}

		// Optional extensions container (context-specific [0]).
		if (ctlSeq.HasData &&
			ctlSeq.PeekTag().TagClass == TagClass.ContextSpecific &&
			ctlSeq.PeekTag().TagValue == 0)
		{
			AsnReader extExplicit = ctlSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
			while (extExplicit.HasData)
			{
				_ = extExplicit.ReadEncodedValue(); // discard!
			}
		}

		// Any trailing data at this point indicates malformed / unexpected content.
		if (ctlSeq.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("UnexpectedTrailingDataCTLElementsError"));
		}

		int entryCountLocal = subjects.Count;

		// Construct the header snapshot.
		CtlHeader header = new(
			version: versionLocal,
			usageOid: usageOidLocal,
			usageFriendlyName: usageFriendlyNameLocal,
			sequenceNumberHexLower: sequenceNumberHexLowerLocal,
			thisUpdateUtc: thisUpdateUtcLocal,
			nextUpdateUtc: nextUpdateUtcLocal,
			algorithmOid: algorithmOidLocal,
			algorithmOidFriendlyName: algorithmOidFriendlyNameLocal,
			digestAlgorithmParameters: algorithmParametersRawLocal,
			entryCount: entryCountLocal
		);

		TrustListParseResult result = new(header, subjects);
		return result;
	}

	/// <summary>
	/// Reads an ASN.1 time value which may be UTCTime or GeneralizedTime; ensures UTC DateTime.
	/// The typical CTL encoding: older lists may use UTCTime while newer may use GeneralizedTime.
	/// </summary>
	private static DateTime ParseAsnTime(AsnReader parent)
	{
		Asn1Tag tag = parent.PeekTag();
		if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.UtcTime)
		{
			DateTimeOffset dto = parent.ReadUtcTime();
			return dto.UtcDateTime;
		}
		if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.GeneralizedTime)
		{
			DateTimeOffset dto = parent.ReadGeneralizedTime();
			return dto.UtcDateTime;
		}
		throw new InvalidDataException("Expected UTCTime or GeneralizedTime, found tag value " + tag.TagValue.ToString(CultureInfo.InvariantCulture) + ".");
	}

	/// <summary>
	/// Converts a bag of raw attributes (OID + value OCTET STRINGs) into a structured Subject.
	/// Enforces presence of FriendlyName, SHA256, and SHA1 identifiers (critical for correct subject matching).
	/// Applies FILETIME conversion for temporal gating attributes (DisabledDate / NotBefore).
	/// </summary>
	private static SubjectEntry MaterializeSubjectEntry(string sha1Fingerprint, List<RawAttribute> attributes)
	{
		string friendlyName = string.Empty;
		string keyID = string.Empty;
		string subjectNameMD5 = string.Empty;
		string sha256Fingerprint = string.Empty;
		DateTime? disabledDate = null;
		DateTime? notBefore = null;
		List<string> msekus = [];
		List<string> notBeforeEkus = [];

		// Iterate each attribute and decode according to its OID semantics.
		for (int i = 0; i < attributes.Count; i++)
		{
			RawAttribute attr = attributes[i];

			if (string.Equals(attr.Oid, OidFriendlyName, StringComparison.OrdinalIgnoreCase))
			{
				if (attr.Values.Count > 0)
				{
					friendlyName = DecodeUTF16LENULLTerminated(attr.Values[0]);
				}
			}
			else if (string.Equals(attr.Oid, OidKeyId, StringComparison.OrdinalIgnoreCase))
			{
				if (attr.Values.Count > 0)
				{
					keyID = Convert.ToHexString(attr.Values[0]);
				}
			}
			else if (string.Equals(attr.Oid, OidSubjectNameMd5, StringComparison.OrdinalIgnoreCase))
			{
				if (attr.Values.Count > 0)
				{
					subjectNameMD5 = Convert.ToHexString(attr.Values[0]);
				}
			}
			else if (string.Equals(attr.Oid, OidSha256Fingerprint, StringComparison.OrdinalIgnoreCase))
			{
				if (attr.Values.Count > 0)
				{
					sha256Fingerprint = Convert.ToHexString(attr.Values[0]);
				}
			}
			else if (string.Equals(attr.Oid, OidEku, StringComparison.OrdinalIgnoreCase) ||
					 string.Equals(attr.Oid, OidNotBeforeEku, StringComparison.OrdinalIgnoreCase))
			{
				if (attr.Values.Count > 0)
				{
					List<string> oids = DecodeEkuSequence(attr.Values[0]);
					if (string.Equals(attr.Oid, OidEku, StringComparison.OrdinalIgnoreCase))
					{
						msekus.AddRange(oids);
					}
					else
					{
						notBeforeEkus.AddRange(oids);
					}
				}
			}
			else if (string.Equals(attr.Oid, OidDisabledDate, StringComparison.OrdinalIgnoreCase))
			{
				// Disabled date present only when Microsoft has explicitly distrusted the subject at/after that date.
				if (attr.Values.Count > 0 && attr.Values[0].Length == 8)
				{
					DateTime dt = FileTimeToDateTime(attr.Values[0]);
					disabledDate = dt;
				}
			}
			else if (string.Equals(attr.Oid, OidNotBeforeDate, StringComparison.OrdinalIgnoreCase))
			{
				// NotBefore gating date for the subject – earlier usage may be treated differently or disallowed.
				if (attr.Values.Count > 0 && attr.Values[0].Length == 8)
				{
					DateTime dt = FileTimeToDateTime(attr.Values[0]);
					notBefore = dt;
				}
			}
		}

		// Enforce required identifiers (reject invalid subjects).
		if (string.IsNullOrEmpty(friendlyName))
		{
			throw new InvalidDataException(GlobalVars.GetStr("SubjectMissingFriendlyNameError"));
		}
		if (string.IsNullOrEmpty(sha256Fingerprint))
		{
			throw new InvalidDataException("Subject '" + friendlyName + "' missing SHA256 fingerprint.");
		}
		if (string.IsNullOrEmpty(sha1Fingerprint))
		{
			throw new InvalidDataException("Subject '" + friendlyName + "' missing SHA1 fingerprint.");
		}

		// Construct the subject
		SubjectEntry subject = new(
			friendlyName: friendlyName,
			sha256Fingerprint: sha256Fingerprint,
			sha1Fingerprint: sha1Fingerprint,
			subjectNameMD5: subjectNameMD5,
			keyID: keyID,
			extendedKeyUsage: msekus,
			disabledDate: disabledDate,
			notBefore: notBefore,
			notBeforeEKU: notBeforeEkus
		);

		return subject;
	}

	/// <summary>
	/// Decodes a DER SEQUENCE of OBJECT IDENTIFIER values (EKUs).
	/// </summary>
	private static List<string> DecodeEkuSequence(ReadOnlySpan<byte> der)
	{
		List<string> oids = [];
		AsnReader seqReader = new(der.ToArray(), AsnEncodingRules.DER);
		AsnReader innerSeq = seqReader.ReadSequence();
		if (seqReader.HasData)
		{
			throw new InvalidDataException(GlobalVars.GetStr("UnexpectedTrailingDataEKUSequenceError"));
		}
		while (innerSeq.HasData)
		{
			string oid = innerSeq.ReadObjectIdentifier();
			oids.Add(oid);
		}
		return oids;
	}

	/// <summary>
	/// Converts an 8-byte Windows FILETIME into a DateTime (UTC)
	/// </summary>
	private static DateTime FileTimeToDateTime(ReadOnlySpan<byte> fileTimeBytes)
	{
		ulong low = BinaryPrimitives.ReadUInt32LittleEndian(fileTimeBytes[..4]);
		ulong high = BinaryPrimitives.ReadUInt32LittleEndian(fileTimeBytes.Slice(4, 4));
		long fileTime = unchecked((long)((high << 32) | low));
		try
		{
			return DateTime.FromFileTimeUtc(fileTime);
		}
		catch (ArgumentOutOfRangeException ex)
		{
			throw new InvalidDataException(GlobalVars.GetStr("InvalidFILETIMEError"), ex);
		}
	}

	/// <summary>
	/// Decodes a UTF‑16LE (little endian) byte sequence that is NUL terminated into a managed string.
	/// Trailing partial byte (odd length) is truncated; search for first 0x0000 pair for termination.
	/// </summary>
	private static string DecodeUTF16LENULLTerminated(ReadOnlySpan<byte> bytes)
	{
		if (bytes.Length == 0)
		{
			return string.Empty;
		}

		// Ensure even length slice; ignore dangling byte if present.
		int length = bytes.Length - (bytes.Length % 2);
		int terminatorIndex = -1;
		for (int i = 0; i < length; i += 2)
		{
			if (bytes[i] == 0 && (i + 1) < length && bytes[i + 1] == 0)
			{
				terminatorIndex = i;
				break;
			}
		}
		ReadOnlySpan<byte> slice = terminatorIndex >= 0 ? bytes[..terminatorIndex] : bytes[..length];
		string value = Encoding.Unicode.GetString(slice);
		return value;
	}

	/// <summary>
	/// Loads a CA certificate from disk.
	/// Supports both PEM (with -----BEGIN CERTIFICATE----- marker) and raw DER.
	/// For PEM files: manual strip & base64 decode.
	/// </summary>
	private static X509Certificate2 LoadCertificate(string path)
	{
		byte[] raw = File.ReadAllBytes(path);
		return LoadCertificateFromBytes(raw);
	}

	/// <summary>
	/// Extracts the base64 block between BEGIN/END CERTIFICATE markers and returns decoded DER bytes.
	/// </summary>
	private static byte[] ExtractPemBlock(byte[] raw)
	{
		string pem = Encoding.ASCII.GetString(raw);
		const string begin = "-----BEGIN CERTIFICATE-----";
		const string end = "-----END CERTIFICATE-----";

		int start = pem.IndexOf(begin, StringComparison.OrdinalIgnoreCase);
		if (start < 0)
		{
			throw new InvalidDataException(GlobalVars.GetStr("BEGINCertificateMarkerNotFoundError"));
		}
		int endIdx = pem.IndexOf(end, start, StringComparison.OrdinalIgnoreCase);
		if (endIdx < 0)
		{
			throw new InvalidDataException(GlobalVars.GetStr("ENDCertificateMarkerNotFoundError"));
		}

		int base64Start = start + begin.Length;
		string base64 = pem[base64Start..endIdx];

		// Manual whitespace removal to safely create a continuous base64 payload.
		StringBuilder sb = new(base64.Length);
		for (int i = 0; i < base64.Length; i++)
		{
			char c = base64[i];
			if (!char.IsWhiteSpace(c) && c != '\r' && c != '\n')
			{
				_ = sb.Append(c);
			}
		}

		try
		{
			return Convert.FromBase64String(sb.ToString());
		}
		catch (FormatException ex)
		{
			throw new InvalidDataException(GlobalVars.GetStr("InvalidBase64ContentError"), ex);
		}
	}

	/// <summary>
	/// Lightweight ASCII detection (first up to 512 bytes) used to decide whether
	/// to attempt PEM marker search (optimization to avoid decoding random binary as ASCII).
	/// </summary>
	private static bool DetectAscii(ReadOnlySpan<byte> bytes)
	{
		int limit = Math.Min(bytes.Length, 512);
		for (int i = 0; i < limit; i++)
		{
			byte b = bytes[i];
			// Reject control chars (except tab-ish range) & high-bit bytes.
			if (b == 0) return false;
			if (b < 0x09) return false;
			if (b > 0x7F) return false;
		}
		return true;
	}

	/// <summary>
	/// Converts a (non-negative) BigInteger into a lowercase hex string (two hex chars per byte).
	/// DER INTEGER sign padding (0x00) is removed upstream by requesting unsigned big-endian.
	/// Used only for the CTL SequenceNumber metadata field.
	/// </summary>
	private static string BigIntegerToLowerHex(BigInteger value)
	{
		if (value < 0)
		{
			// Sequence number expected non-negative. If negative, flip (defensive).
			value = BigInteger.Negate(value);
		}
		byte[] bigEndian = value.ToByteArray(isUnsigned: true, isBigEndian: true);
		StringBuilder sb = new(bigEndian.Length * 2);
		for (int i = 0; i < bigEndian.Length; i++)
		{
			_ = sb.Append(bigEndian[i].ToString("x2", CultureInfo.InvariantCulture));
		}
		return sb.ToString();
	}

	/// <summary>
	/// Internal lightweight raw attribute representation (OID + list of OCTET STRING blobs).
	/// This is for the nested structure inside TrustedSubjects where each attribute has a SET OF values.
	/// </summary>
	private readonly struct RawAttribute(string oid, List<byte[]> values)
	{
		internal string Oid { get; } = oid;
		internal List<byte[]> Values { get; } = values;
	}

	/// <summary>
	/// Builds a case-insensitive set of STL root SHA256 fingerprints for fast lookup.
	/// </summary>
	internal static HashSet<string> BuildStlRootSha256Set(IEnumerable<SubjectEntry> subjects)
	{
		HashSet<string> set = new(StringComparer.OrdinalIgnoreCase);
		foreach (SubjectEntry s in subjects)
		{
			if (!string.IsNullOrEmpty(s.SHA256Fingerprint))
			{
				_ = set.Add(s.SHA256Fingerprint);
			}
		}
		return set;
	}

	/// <summary>
	/// Enumerate certificates across CurrentUser and LocalMachine stores and return those whose chain root
	/// is NOT present in the provided STL root SHA256 set.
	/// includeExpired: when false, only time-valid (now within NotBefore..NotAfter) leaf certificates are considered.
	/// Note: includeExpired=false also excludes "not yet valid" certificates.
	/// </summary>
	internal static List<NonStlRootCert> FindCertificatesNotChainingToStlRoots(HashSet<string> stlRootSha256Hex, bool includeExpired)
	{
		List<NonStlRootCert> results = [];
		Dictionary<string, string> rootSha256CacheByRootSha1 = new(StringComparer.OrdinalIgnoreCase);

		DateTime nowUtc = DateTime.UtcNow;

		for (int l = 0; l < storeLocations.Length; l++)
		{
			StoreLocation loc = storeLocations[l];

			for (int s = 0; s < knownStoreNames.Length; s++)
			{
				string storeName = knownStoreNames[s];

				try
				{
					using X509Store store = new(storeName, loc);
					store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived | OpenFlags.MaxAllowed);

					X509Certificate2Collection certs = store.Certificates;
					for (int i = 0; i < certs.Count; i++)
					{
						X509Certificate2 leaf = certs[i];

						string leafSha1 = leaf.Thumbprint ?? string.Empty;
						if (string.IsNullOrEmpty(leafSha1))
						{
							continue;
						}

						// Time-valid filtering (applies to leaf). When includeExpired=false,
						// we exclude both expired and not-yet-valid certificates.
						if (!includeExpired)
						{
							DateTime notBeforeUtc = leaf.NotBefore.Kind == DateTimeKind.Utc ? leaf.NotBefore : leaf.NotBefore.ToUniversalTime();
							DateTime notAfterUtc = leaf.NotAfter.Kind == DateTimeKind.Utc ? leaf.NotAfter : leaf.NotAfter.ToUniversalTime();
							if (nowUtc < notBeforeUtc || nowUtc > notAfterUtc)
							{
								continue;
							}
						}

						// Determine the chain root and its SHA256.
						X509Certificate2? rootCert = TryGetChainRoot(leaf);
						string rootSubject = rootCert is null ? "(no root)" : rootCert.Subject;

						string rootSha1 = rootCert is null ? "(none)" : (rootCert.Thumbprint ?? "(none)");
						string rootSha256Hex;

						if (!rootSha256CacheByRootSha1.TryGetValue(rootSha1, out rootSha256Hex!))
						{
							rootSha256Hex = ComputeCertSha256Hex(rootCert);
							rootSha256CacheByRootSha1[rootSha1] = rootSha256Hex;
						}

						// If no root or not in STL set, include.
						if (string.IsNullOrEmpty(rootSha256Hex) || !stlRootSha256Hex.Contains(rootSha256Hex))
						{
							NonStlRootCert item = new(
								storeLocationString: loc.ToString(),
								storeNameString: storeName.ToString(),
								subject: leaf.Subject,
								issuer: leaf.Issuer,
								leafThumbprintSha1: leafSha1,
								rootSubject: rootSubject,
								rootSha256Hex: string.IsNullOrEmpty(rootSha256Hex) ? "(none)" : rootSha256Hex
							);
							results.Add(item);
						}
					}
				}
				catch
				{
					// Silently skip inaccessible/non-existent stores.
				}
			}
		}

		return results;
	}

	/// <summary>
	/// Attempts to build a chain and return the last element (root). Returns null if no chain elements were built.
	/// Uses system trust; allows unknown/expired to still materialize a chain.
	/// </summary>
	private static X509Certificate2? TryGetChainRoot(X509Certificate2 cert)
	{
		using X509Chain chain = new()
		{
			ChainPolicy =
			{
				RevocationMode = X509RevocationMode.NoCheck,
				RevocationFlag = X509RevocationFlag.ExcludeRoot,
				VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.AllowUnknownCertificateAuthority
			}
		};
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;

		try
		{
			_ = chain.Build(cert);
		}
		catch
		{
			// Ignore build exceptions; we only care about any ChainElements captured.
		}

		if (chain.ChainElements.Count > 0)
		{
			return chain.ChainElements[^1].Certificate;
		}

		// As a fallback, treat a self-issued leaf as its own root if subject==issuer.
		if (IsSelfIssued(cert))
		{
			return cert;
		}

		return null;
	}

	/// <summary>
	/// Computes uppercase hex SHA256 of the certificate's raw data. Returns empty string if cert is null.
	/// </summary>
	private static string ComputeCertSha256Hex(X509Certificate2? cert)
	{
		if (cert is null)
		{
			return string.Empty;
		}
		byte[] hash = SHA256.HashData(cert.RawData);
		return Convert.ToHexString(hash);
	}

	/// <summary>
	/// Lightweight self-issued check based on Subject/Issuer string equality.
	/// </summary>
	private static bool IsSelfIssued(X509Certificate2 cert)
	{
		string subject = cert.Subject ?? string.Empty;
		string issuer = cert.Issuer ?? string.Empty;
		return subject.Equals(issuer, StringComparison.OrdinalIgnoreCase);
	}
}

internal static partial class CabinetArchiveExtractor
{
	/// <summary>
	/// Not used anywhere at the moment, we process everything in the memory.
	/// </summary>
	/// <param name="cabinetFilePath"></param>
	/// <param name="extractionRootDirectoryPath"></param>
	internal static void ExtractCabinet(string cabinetFilePath, string extractionRootDirectoryPath)
	{
		_ = Directory.CreateDirectory(extractionRootDirectoryPath);

		byte[] cabinetBytes = ReadAllBytes(cabinetFilePath);

		using CabinetDecompressionContext decompressionContext = new(cabinetBytes, cabinetEntry =>
		{
			string sanitizedName = SanitizeRelativePath(cabinetEntry.Name);
			if (string.IsNullOrWhiteSpace(sanitizedName))
			{
				Logger.Write(GlobalVars.GetStr("EmptyEntryNameSkippingMessage"));
				return;
			}

			string destinationFilePath = Path.GetFullPath(Path.Combine(extractionRootDirectoryPath, sanitizedName));

			if (!destinationFilePath.StartsWith(extractionRootDirectoryPath, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write("Entry is outside extraction root: " + cabinetEntry.Name);
				return;
			}

			string? destinationDirectoryPath = Path.GetDirectoryName(destinationFilePath);
			if (!string.IsNullOrEmpty(destinationDirectoryPath))
			{
				_ = Directory.CreateDirectory(destinationDirectoryPath);
			}

			File.WriteAllBytes(destinationFilePath, cabinetEntry.Data.ToArray());
			try
			{
				File.SetLastWriteTime(destinationFilePath, cabinetEntry.LastWriteTime);
			}
			catch
			{ }
		});

		decompressionContext.Run();
	}

	private static string SanitizeRelativePath(string candidateName)
	{
		if (string.IsNullOrWhiteSpace(candidateName))
		{
			return string.Empty;
		}

		string normalized = candidateName.Replace('\\', '/');

		while (normalized.StartsWith("./", StringComparison.OrdinalIgnoreCase))
		{
			if (normalized.Length <= 2)
			{
				normalized = "";
				break;
			}
			normalized = normalized[2..];
		}

		if (normalized.Contains("../", StringComparison.OrdinalIgnoreCase))
		{
			string[] pathSegments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
			List<string> safeSegments = [];
			for (int i = 0; i < pathSegments.Length; i++)
			{
				if (pathSegments[i] == "..")
				{
					continue;
				}
				safeSegments.Add(pathSegments[i]);
			}
			normalized = string.Join("/", safeSegments);
		}

		normalized = normalized.TrimStart('/', '\\');

		if (string.IsNullOrWhiteSpace(normalized))
		{
			normalized = "cab_entry_missing_name";
		}

		return normalized;
	}

	private static byte[] ReadAllBytes(string filePath)
	{
		using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
		using MemoryStream memoryStream = new();
		fileStream.CopyTo(memoryStream);
		return memoryStream.ToArray();
	}

	internal sealed partial class CabinetDecompressionContext : IDisposable
	{
		private readonly byte[] cabinetContentBytes;
		private readonly Dictionary<IntPtr, object> syntheticHandleTable;
		private MemoryStream? currentFileAccumulationStream;
		private readonly Action<CabinetFileEntry> entryCallback;
		private FdiErrorInfo fdiErrorInfo;
		private GCHandle fdiErrorInfoHandle;
		private IntPtr fdiContextHandle;
		private bool isDisposed;

		// Thread-affine context for unmanaged callbacks (FDI invokes callbacks on the calling thread).
		// We set this before FDICreate/FDICopy/FDIDestroy so static unmanaged callbacks can reach the instance.
		[ThreadStatic]
		private static CabinetDecompressionContext? s_current;

		internal unsafe CabinetDecompressionContext(byte[] decompressionBytes, Action<CabinetFileEntry> extractedEntryCallback)
		{
			cabinetContentBytes = decompressionBytes;
			entryCallback = extractedEntryCallback;

			syntheticHandleTable = [];

			fdiErrorInfo = new FdiErrorInfo();
			fdiErrorInfoHandle = GCHandle.Alloc(fdiErrorInfo, GCHandleType.Pinned);

			// Creating the FDI context using unmanaged function pointers (cdecl).
			// FDICreate may call pfnalloc/pfnfree during creation. Ensure callbacks can reach this instance.
			s_current = this;

			IntPtr pfnalloc;
			IntPtr pfnfree;
			IntPtr pfnopen;
			IntPtr pfnread;
			IntPtr pfnwrite;
			IntPtr pfnclose;
			IntPtr pfnseek;

			unsafe
			{
				pfnalloc = (IntPtr)(delegate* unmanaged[Cdecl]<int, IntPtr>)&FdiAlloc_Unmanaged;
				pfnfree = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, void>)&FdiFree_Unmanaged;
				pfnopen = (IntPtr)(delegate* unmanaged[Cdecl]<byte*, int, int, IntPtr>)&FdiOpen_Unmanaged;
				pfnread = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int, int>)&FdiRead_Unmanaged;
				pfnwrite = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int, int>)&FdiWrite_Unmanaged;
				pfnclose = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int>)&FdiClose_Unmanaged;
				pfnseek = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, SeekOrigin, int>)&FdiSeek_Unmanaged;
			}

			try
			{
				fdiContextHandle = NativeMethods.FDICreate(
					pfnalloc,
					pfnfree,
					pfnopen,
					pfnread,
					pfnwrite,
					pfnclose,
					pfnseek,
					0,
					fdiErrorInfoHandle.AddrOfPinnedObject());
			}
			finally
			{
				// clear thread-affine context even if FDICreate throws.
				s_current = null;
			}

			if (fdiContextHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("FDICreate failed (erfOper=" + fdiErrorInfo.erfOper.ToString(CultureInfo.InvariantCulture) + ")");
			}
		}

		~CabinetDecompressionContext()
		{
			Dispose(false);
		}

		internal void Run()
		{
			ObjectDisposedException.ThrowIf(isDisposed, this);

			// FDICopy invokes the notify callback and then the stream callbacks (all on this thread).
			s_current = this;

			bool success;
			IntPtr fnNotify;

			unsafe
			{
				fnNotify = (IntPtr)(delegate* unmanaged[Cdecl]<FdiNotificationType, FdiNotificationRecord*, IntPtr>)&FdiNotify_Unmanaged;
			}

			try
			{
				success = NativeMethods.FDICopy(
					fdiContextHandle,
					string.Empty,
					string.Empty,
					0,
					fnNotify,
					IntPtr.Zero,
					IntPtr.Zero);
			}
			finally
			{
				// Clear thread context to avoid accidental bleed if caller reuses the same thread for other operations.
				s_current = null;
			}

			if (!success)
			{
				throw new InvalidOperationException("FDICopy failed (erfOper=" + fdiErrorInfo.erfOper.ToString(CultureInfo.InvariantCulture) + ")");
			}
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		private void Dispose(bool disposing)
		{
			if (isDisposed)
			{
				return;
			}
			isDisposed = true;

			if (fdiContextHandle != IntPtr.Zero)
			{
				try
				{
					// FDIDestroy may call the provided free callback; ensure thread-context is set.
					s_current = this;
					_ = NativeMethods.FDIDestroy(fdiContextHandle);
				}
				catch
				{
					// Ignore failures
				}
				finally
				{
					s_current = null;
				}
				fdiContextHandle = IntPtr.Zero;
			}

			if (fdiErrorInfoHandle.IsAllocated)
			{
				fdiErrorInfoHandle.Free();
			}

			if (disposing)
			{
				if (currentFileAccumulationStream != null)
				{
					try { currentFileAccumulationStream.Dispose(); }
					catch { }
					currentFileAccumulationStream = null;
				}
				syntheticHandleTable.Clear();
			}
		}

		private IntPtr AllocateFdiBuffer(int byteCount)
		{
			IntPtr unmanagedPtr = Marshal.AllocHGlobal(byteCount);
			unsafe
			{
				Span<byte> clearSpan = new((void*)unmanagedPtr, byteCount);
				clearSpan.Clear();
			}
			return unmanagedPtr;
		}

		private void FreeFdiBuffer(IntPtr bufferPointer)
		{
			if (bufferPointer != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(bufferPointer);
			}
		}

		private unsafe IntPtr OpenCabinetStream(byte* pszFile, int oflag, int pmode)
		{
			IntPtr syntheticHandle = new(syntheticHandleTable.Count + 1);
			syntheticHandleTable.Add(syntheticHandle, 0);
			return syntheticHandle;
		}

		private int ReadCabinetStream(IntPtr handle, IntPtr destinationBuffer, int requestedBytes)
		{
			// Look up current read position for the synthetic handle
			if (!syntheticHandleTable.TryGetValue(handle, out object? posObj))
			{
				return -1; // signal error to FDI
			}

			int currentPosition = (int)posObj;
			int remaining = cabinetContentBytes.Length - currentPosition;
			int bytesToRead = remaining < requestedBytes ? remaining : requestedBytes;

			if (bytesToRead > 0)
			{
				// Copy from managed CAB buffer into native buffer (provided by FDI)
				Marshal.Copy(cabinetContentBytes, currentPosition, destinationBuffer, bytesToRead);
				syntheticHandleTable[handle] = currentPosition + bytesToRead;
			}

			return bytesToRead;
		}

		private int WriteDecompressedData(IntPtr handle, IntPtr sourceBuffer, int sourceCount)
		{
			if (currentFileAccumulationStream == null)
			{
				return -1; // no active output stream
			}
			if (sourceCount <= 0)
			{
				return 0;
			}

			// Copy from native buffer (FDI output) into our accumulation stream
			byte[] temp = System.Buffers.ArrayPool<byte>.Shared.Rent(sourceCount);
			try
			{
				Marshal.Copy(sourceBuffer, temp, 0, sourceCount);
				currentFileAccumulationStream.Write(temp, 0, sourceCount);
			}
			finally
			{
				System.Buffers.ArrayPool<byte>.Shared.Return(temp);
			}

			return sourceCount;
		}

		private int CloseHandleOrEntry(IntPtr handle)
		{
			if (syntheticHandleTable.TryGetValue(handle, out object? stored))
			{
				if (stored is CabinetFileEntry entry && currentFileAccumulationStream != null)
				{
					entry.Data = currentFileAccumulationStream.ToArray();
					currentFileAccumulationStream.Dispose();
					currentFileAccumulationStream = null;
				}
				_ = syntheticHandleTable.Remove(handle);
			}
			return 0;
		}

		private int SeekCabinetStream(IntPtr handle, int distance, SeekOrigin origin)
		{
			if (!syntheticHandleTable.TryGetValue(handle, out object? posObj))
			{
				return -1;
			}

			int basePosition = (int)posObj;
			int newPosition = origin switch
			{
				SeekOrigin.Begin => distance,
				SeekOrigin.Current => basePosition + distance,
				_ => cabinetContentBytes.Length + distance
			};

			if (newPosition < 0)
			{
				newPosition = 0;
			}
			if (newPosition > cabinetContentBytes.Length)
			{
				newPosition = cabinetContentBytes.Length;
			}
			syntheticHandleTable[handle] = newPosition;
			return newPosition;
		}

		private unsafe IntPtr HandleFdiNotification(FdiNotificationType notificationType, FdiNotificationRecord* notificationRecord)
		{
			switch (notificationType)
			{
				case FdiNotificationType.COPY_FILE:
					{
						// Copy the struct value
						FdiNotificationRecord record = *notificationRecord;

						// Begin a new file entry and prepare to accumulate its data
						CabinetFileEntry entry = new(record)
						{
							_handle = new IntPtr(syntheticHandleTable.Count + 1)
						};
						syntheticHandleTable.Add(entry._handle, entry);
						currentFileAccumulationStream = new MemoryStream();
						return entry._handle;
					}

				case FdiNotificationType.CLOSE_FILE_INFO:
					{
						// Finish accumulating the file and emit it through the callback
						if (syntheticHandleTable.TryGetValue(notificationRecord->hf, out object? stored) && stored is CabinetFileEntry entry)
						{
							_ = CloseHandleOrEntry(notificationRecord->hf);
							entryCallback(entry);
							return new IntPtr(1); // success/continue
						}
						return IntPtr.Zero; // abort if handle was unknown
					}

				case FdiNotificationType.CABINET_INFO:
					// Got to return non-zero here to allow FDICopy to proceed
					return new IntPtr(1);

				case FdiNotificationType.ENUMERATE:
					// Not used; returning non-zero is the safe "continue"
					return new IntPtr(1);

				case FdiNotificationType.PARTIAL_FILE:
					// Not supporting partial files; return 0 to skip/abort this entry
					return IntPtr.Zero;

				case FdiNotificationType.NEXT_CABINET:
					// Not supporting spanned cabinets; returning 0 will abort here
					return IntPtr.Zero;

				default:
					return IntPtr.Zero;
			}
		}

		#region Unmanaged (cdecl) callbacks

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static IntPtr FdiAlloc_Unmanaged(int cb)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? IntPtr.Zero : ctx.AllocateFdiBuffer(cb);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static void FdiFree_Unmanaged(IntPtr pv)
		{
			CabinetDecompressionContext? ctx = s_current;
			if (ctx is null)
			{
				return;
			}
			ctx.FreeFdiBuffer(pv);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static unsafe IntPtr FdiOpen_Unmanaged(byte* pszFile, int oflag, int pmode)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? IntPtr.Zero : ctx.OpenCabinetStream(pszFile, oflag, pmode);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static int FdiRead_Unmanaged(IntPtr hf, IntPtr pv, int cb)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? -1 : ctx.ReadCabinetStream(hf, pv, cb);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static int FdiWrite_Unmanaged(IntPtr hf, IntPtr pv, int cb)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? -1 : ctx.WriteDecompressedData(hf, pv, cb);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static int FdiClose_Unmanaged(IntPtr hf)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? 0 : ctx.CloseHandleOrEntry(hf);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static int FdiSeek_Unmanaged(IntPtr hf, int dist, SeekOrigin seektype)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? -1 : ctx.SeekCabinetStream(hf, dist, seektype);
		}

		[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		private static unsafe IntPtr FdiNotify_Unmanaged(FdiNotificationType fdint, FdiNotificationRecord* pfdin)
		{
			CabinetDecompressionContext? ctx = s_current;
			return ctx is null ? IntPtr.Zero : ctx.HandleFdiNotification(fdint, pfdin);
		}

		#endregion
	}

	private enum FdiNotificationType
	{
		CABINET_INFO = 0,
		PARTIAL_FILE = 1,
		COPY_FILE = 2,
		CLOSE_FILE_INFO = 3,
		NEXT_CABINET = 4,
		ENUMERATE = 5,
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct FdiErrorInfo
	{
		internal int erfOper;
		internal int erfType;
		internal int fError;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
	internal struct FdiNotificationRecord
	{
		internal int cb;
		internal IntPtr psz1;
		internal IntPtr psz2;
		internal IntPtr psz3;
		internal IntPtr pv;
		internal IntPtr hf;
		internal ushort date;
		internal ushort time;
		internal ushort attribs;
		internal ushort setID;
		internal ushort iCabinet;
		internal ushort iFolder;
		internal int fdie;
	}

	internal sealed class CabinetFileEntry
	{
		internal IntPtr _handle;
		internal string Name { get; private set; }
		internal int Size { get; private set; }
		internal DateTime LastWriteTime { get; private set; }
		internal ReadOnlyMemory<byte> Data { get; set; }

		internal CabinetFileEntry(FdiNotificationRecord notificationRecord)
		{
			string? rawName = Marshal.PtrToStringAnsi(notificationRecord.psz1);
			if (string.IsNullOrEmpty(rawName))
			{
				rawName = "cab_entry_missing_name";
			}
			Name = rawName;
			Size = notificationRecord.cb;

			int year = ((notificationRecord.date >> 9) & 0x7F) + 1980;
			int month = (notificationRecord.date >> 5) & 0x0F;
			int day = notificationRecord.date & 0x1F;
			int hour = (notificationRecord.time >> 11) & 0x1F;
			int minute = (notificationRecord.time >> 5) & 0x3F;
			int second = (notificationRecord.time & 0x1F) * 2;

			try
			{
				LastWriteTime = new DateTime(year, month == 0 ? 1 : month, day == 0 ? 1 : day, hour, minute, second, DateTimeKind.Local);
			}
			catch
			{
				LastWriteTime = DateTime.Now;
			}
		}
	}
}
