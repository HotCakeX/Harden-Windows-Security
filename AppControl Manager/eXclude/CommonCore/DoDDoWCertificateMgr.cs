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
using System.Formats.Asn1;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CommonCore;

internal static class DoDDoWCertificateMgr
{
	private static readonly Uri DoDPkiCertificateBundleUri = new("https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip");
	private static readonly Uri CloudflareDnsOverHttpsJsonEndpoint = new("https://cloudflare-dns.com/dns-query");
	private static readonly Asn1Tag ContextSpecificZeroAsn1Tag = new(TagClass.ContextSpecific, 0);
	private static readonly Asn1Tag UniversalSequenceAsn1Tag = new(UniversalTagNumber.Sequence);
	private const string DnsOverHttpsJsonMediaType = "application/dns-json";
	private const string Pkcs7SignedDataObjectIdentifier = "1.2.840.113549.1.7.2";
	private const string PemCertificateBeginMarker = "-----BEGIN CERTIFICATE-----";
	private const string PemCertificateEndMarker = "-----END CERTIFICATE-----";
	private const string PemBeginMarker = "-----BEGIN";
	private const string PemEndMarker = "-----END";
	private const int DnsResponseCodeNoError = 0;
	private const int DnsRecordTypeAddress = 1;
	private const string DoDPkeCaChainFileName = "DoD_PKE_CA_chain.pem";
	private const string DoDPkiBundleChecksumSignatureExtension = ".sha256";

	/// <summary>
	/// This list must be reviewed when DoD/DoW introduces a new root CA.
	/// </summary>
	private static readonly HashSet<string> KnownDoDRootCaSha1Thumbprints = new(StringComparer.OrdinalIgnoreCase)
	{
		"D73CA91102A2204A36459ED32213B467D7CE97FB",
		"B8269F25DBD937ECAFD4C35A9838571723F2D026",
		"4ECB5CC3095670454DA1CBD410FC921F46B8564B",
		"D37ECF61C0B4ED88681EF3630C4E2FC787B37AEF"
	};

	/// <summary>
	/// Performs the DoD certificate operation using only in-memory download, ZIP processing, and certificate parsing.
	/// </summary>
	internal static async Task<DoDCertificateOperationResult> ConfigureDoDCertificatesInternalAsync(bool install)
	{
		List<X509Certificate2> certificates = await DownloadDoDCertificatesFromOfficialBundleAsync();
		try
		{
			return ApplyDoDCertificateStoreChanges(certificates, install);
		}
		finally
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				certificate.Dispose();
			}
		}
	}

	/// <summary>
	/// Downloads the official DoD PKI bundle and imports all PKCS#7 certificate entries from memory.
	/// </summary>
	private static async Task<List<X509Certificate2>> DownloadDoDCertificatesFromOfficialBundleAsync()
	{
		using HttpClient dnsOverHttpsHttpClient = new();
		using SocketsHttpHandler socketsHttpHandler = new()
		{
			PooledConnectionLifetime = TimeSpan.FromSeconds(30)
		};

		socketsHttpHandler.ConnectCallback = async (context, cancellationToken) =>
		{
			DnsEndPoint dnsEndPoint = context.DnsEndPoint;
			IPAddress[] addresses = await ResolveAddressRecordsWithCloudflareDnsOverHttpsAsync(dnsOverHttpsHttpClient, dnsEndPoint.Host, cancellationToken);
			Socket socket = new(SocketType.Stream, ProtocolType.Tcp)
			{
				NoDelay = true
			};
			bool socketOwnershipTransferred = false;

			try
			{
				await socket.ConnectAsync(addresses, dnsEndPoint.Port, cancellationToken);
				NetworkStream networkStream = new(socket, ownsSocket: true);
				socketOwnershipTransferred = true;
				return networkStream;
			}
			finally
			{
				if (!socketOwnershipTransferred)
				{
					socket.Dispose();
				}
			}
		};

		using HttpClient httpClient = new(socketsHttpHandler, disposeHandler: false);
		byte[] zipBytes = await httpClient.GetByteArrayAsync(DoDPkiCertificateBundleUri);
		using MemoryStream zipStream = new(zipBytes, writable: false);
		using ZipArchive zipArchive = new(zipStream, ZipArchiveMode.Read, leaveOpen: false);
		Dictionary<string, byte[]> zipEntries = await ReadZipEntriesIntoMemoryAsync(zipArchive);
		VerifyDoDPkiBundle(zipEntries);

		List<X509Certificate2> certificates = [];
		bool certificatesOwnershipTransferred = false;
		try
		{
			HashSet<string> thumbprints = new(StringComparer.OrdinalIgnoreCase);
			foreach (KeyValuePair<string, byte[]> entry in zipEntries)
			{
				if (!IsSupportedCertificateBundleEntry(entry.Key))
				{
					continue;
				}

				List<byte[]> certificateDerData = ExtractCertificateDerData(entry.Key, entry.Value);
				foreach (byte[] certificateDerBytes in CollectionsMarshal.AsSpan(certificateDerData))
				{
					X509Certificate2? certificate = null;
					bool certificateOwnershipTransferred = false;
					try
					{
						certificate = X509CertificateLoader.LoadCertificate(certificateDerBytes);
						if (string.IsNullOrWhiteSpace(certificate.Thumbprint) || !thumbprints.Add(certificate.Thumbprint))
						{
							continue;
						}

						certificates.Add(certificate);
						certificateOwnershipTransferred = true;
					}
					catch (CryptographicException ex)
					{
						Logger.Write(ex);
					}
					finally
					{
						if (!certificateOwnershipTransferred)
						{
							certificate?.Dispose();
						}
					}
				}
			}

			if (certificates.Count is 0)
			{
				throw new InvalidOperationException("The DoD PKI bundle did not contain any importable certificates.");
			}

			certificatesOwnershipTransferred = true;
			return certificates;
		}
		finally
		{
			if (!certificatesOwnershipTransferred)
			{
				foreach (X509Certificate2 certificate in CollectionsMarshal.AsSpan(certificates))
				{
					certificate.Dispose();
				}
			}
		}
	}

	/// <summary>
	/// Resolves IPv4 address records for a host by querying Cloudflare's DNS over HTTPS JSON endpoint.
	/// Because some ISPs or VPN providers might not resolve DoD domains correctly and also this protects against possible poisoned DNS cache.
	/// </summary>
	private static async Task<IPAddress[]> ResolveAddressRecordsWithCloudflareDnsOverHttpsAsync(HttpClient dnsOverHttpsHttpClient, string hostName, CancellationToken cancellationToken)
	{
		if (IPAddress.TryParse(hostName, out IPAddress? literalAddress))
		{
			return [literalAddress];
		}

		UriBuilder requestUriBuilder = new(CloudflareDnsOverHttpsJsonEndpoint)
		{
			Query = $"name={Uri.EscapeDataString(hostName)}&type=A"
		};

		using HttpRequestMessage request = new(HttpMethod.Get, requestUriBuilder.Uri);
		request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DnsOverHttpsJsonMediaType));

		using HttpResponseMessage response = await dnsOverHttpsHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
		_ = response.EnsureSuccessStatusCode();

		using Stream responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
		using JsonDocument responseDocument = await JsonDocument.ParseAsync(responseStream, cancellationToken: cancellationToken);
		JsonElement rootElement = responseDocument.RootElement;

		if (!rootElement.TryGetProperty("Status", out JsonElement statusElement) || statusElement.GetInt32() is not DnsResponseCodeNoError)
		{
			throw new InvalidOperationException($"Cloudflare DNS over HTTPS did not return a successful DNS response for {hostName}.");
		}

		if (!rootElement.TryGetProperty("Answer", out JsonElement answerElement) || answerElement.ValueKind is not JsonValueKind.Array)
		{
			throw new InvalidOperationException($"Cloudflare DNS over HTTPS did not return address records for {hostName}.");
		}

		List<IPAddress> addresses = [];
		foreach (JsonElement recordElement in answerElement.EnumerateArray())
		{
			if (!recordElement.TryGetProperty("type", out JsonElement recordTypeElement) || recordTypeElement.GetInt32() is not DnsRecordTypeAddress)
			{
				continue;
			}

			if (!recordElement.TryGetProperty("data", out JsonElement recordDataElement))
			{
				continue;
			}

			string? recordData = recordDataElement.GetString();
			if (recordData is null || !IPAddress.TryParse(recordData, out IPAddress? address))
			{
				continue;
			}

			addresses.Add(address);
		}

		if (addresses.Count is 0)
		{
			throw new InvalidOperationException($"Cloudflare DNS over HTTPS did not return usable IPv4 address records for {hostName}.");
		}

		return [.. addresses];
	}

	/// <summary>
	/// Reads every ZIP file entry into memory so the signed manifest can be verified before certificates are trusted.
	/// </summary>
	private static async Task<Dictionary<string, byte[]>> ReadZipEntriesIntoMemoryAsync(ZipArchive zipArchive)
	{
		Dictionary<string, byte[]> zipEntries = new(StringComparer.OrdinalIgnoreCase);
		foreach (ZipArchiveEntry entry in zipArchive.Entries)
		{
			if (string.IsNullOrWhiteSpace(entry.Name))
			{
				continue;
			}

			string normalizedEntryName = NormalizeZipEntryName(entry.FullName);
			using Stream entryStream = await entry.OpenAsync();
			using MemoryStream entryBytesStream = new();
			await entryStream.CopyToAsync(entryBytesStream);
			if (!zipEntries.TryAdd(normalizedEntryName, entryBytesStream.ToArray()))
			{
				throw new InvalidOperationException($"The DoD PKI bundle contains a duplicate ZIP entry named {normalizedEntryName}.");
			}
		}

		return zipEntries;
	}

	/// <summary>
	/// Verifies the DoD PKI ZIP bundle using the documented signing chain, S/MIME signature, and SHA-256 manifest.
	/// The document is included in the zip bundle.
	/// </summary>
	private static void VerifyDoDPkiBundle(IReadOnlyDictionary<string, byte[]> zipEntries)
	{
		byte[] signingChainBytes = GetRequiredZipEntryBytes(zipEntries, DoDPkeCaChainFileName);
		List<byte[]> signingChainCertificateDerData = DecodePemCertificateBlocks(signingChainBytes);
		if (signingChainCertificateDerData.Count is not 2)
		{
			throw new InvalidOperationException($"{DoDPkeCaChainFileName} must contain exactly one DoD root CA and one subordinate CA.");
		}

		X509Certificate2? rootCertificate = null;
		X509Certificate2? subordinateCertificate = null;
		try
		{
			rootCertificate = X509CertificateLoader.LoadCertificate(signingChainCertificateDerData[0]);
			subordinateCertificate = X509CertificateLoader.LoadCertificate(signingChainCertificateDerData[1]);
			ValidateDoDPkiSigningChain(rootCertificate, subordinateCertificate);
			byte[] signedChecksumBytes = GetSignedChecksumEntryBytes(zipEntries);
			byte[] checksumPayload = VerifySignedChecksumPayload(signedChecksumBytes);
			ValidateSignedChecksumSigners(signedChecksumBytes, rootCertificate, subordinateCertificate);
			VerifyChecksumPayloadAgainstZipEntries(checksumPayload, zipEntries);
		}
		finally
		{
			rootCertificate?.Dispose();
			subordinateCertificate?.Dispose();
		}
	}

	/// <summary>
	/// Validates that DoD_PKE_CA_chain.pem contains a known DoD root CA and one subordinate CA issued by it.
	/// </summary>
	private static void ValidateDoDPkiSigningChain(X509Certificate2 rootCertificate, X509Certificate2 subordinateCertificate)
	{
		if (!rootCertificate.SubjectName.RawData.AsSpan().SequenceEqual(rootCertificate.IssuerName.RawData))
		{
			throw new InvalidOperationException($"The first certificate in {DoDPkeCaChainFileName} is not self-issued.");
		}

		if (!rootCertificate.Subject.Contains("CN=DoD Root CA", StringComparison.OrdinalIgnoreCase) || !rootCertificate.Subject.Contains("OU=DoD", StringComparison.OrdinalIgnoreCase) || !rootCertificate.Subject.Contains("OU=PKI", StringComparison.OrdinalIgnoreCase) || !rootCertificate.Subject.Contains("O=U.S. Government", StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException($"The first certificate in {DoDPkeCaChainFileName} is not a recognized DoD root CA subject.");
		}

		if (string.IsNullOrWhiteSpace(rootCertificate.Thumbprint) || !KnownDoDRootCaSha1Thumbprints.Contains(rootCertificate.Thumbprint))
		{
			throw new InvalidOperationException($"The DoD root CA thumbprint {rootCertificate.Thumbprint} is not in the known DoD Root CA 3, 4, 5, or 6 thumbprint set.");
		}

		if (!IsCertificateAuthority(rootCertificate) || !IsCertificateAuthority(subordinateCertificate))
		{
			throw new InvalidOperationException("The DoD PKE signing chain contains a certificate that is not marked as a certificate authority.");
		}

		if (subordinateCertificate.SubjectName.RawData.AsSpan().SequenceEqual(subordinateCertificate.IssuerName.RawData) || !subordinateCertificate.IssuerName.RawData.AsSpan().SequenceEqual(rootCertificate.SubjectName.RawData))
		{
			throw new InvalidOperationException($"The second certificate in {DoDPkeCaChainFileName} is not a subordinate CA issued by the first certificate.");
		}
	}

	/// <summary>
	/// Verifies the DER encoded S/MIME signature over the checksum manifest and returns the signed payload.
	/// </summary>
	private static byte[] VerifySignedChecksumPayload(byte[] signedChecksumBytes)
	{
		SignedCms signedCms = new();
		signedCms.Decode(signedChecksumBytes);
		signedCms.CheckSignature(verifySignatureOnly: true);
		if (signedCms.ContentInfo.Content.Length is 0)
		{
			throw new InvalidOperationException("The signed DoD checksum manifest did not contain an embedded payload.");
		}

		return signedCms.ContentInfo.Content;
	}

	/// <summary>
	/// Validates each CMS signer against the DoD PKE chain without requiring the root to be installed first.
	/// </summary>
	private static void ValidateSignedChecksumSigners(byte[] signedChecksumBytes, X509Certificate2 rootCertificate, X509Certificate2 subordinateCertificate)
	{
		SignedCms signedCms = new();
		signedCms.Decode(signedChecksumBytes);
		if (signedCms.SignerInfos.Count is 0)
		{
			throw new InvalidOperationException("The DoD checksum manifest does not contain a signer.");
		}

		foreach (SignerInfo signerInfo in signedCms.SignerInfos)
		{
			X509Certificate2? signerCertificate = signerInfo.Certificate ?? throw new InvalidOperationException("The DoD checksum manifest signer certificate is not embedded in the CMS object.");
			using X509Chain signerChain = new();
			signerChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
			_ = signerChain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
			_ = signerChain.ChainPolicy.ExtraStore.Add(subordinateCertificate);
			foreach (X509Certificate2 cmsCertificate in signedCms.Certificates)
			{
				_ = signerChain.ChainPolicy.ExtraStore.Add(cmsCertificate);
			}

			signerChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
			signerChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
			if (!signerChain.Build(signerCertificate))
			{
				throw new InvalidOperationException($"The DoD checksum manifest signer did not chain to the DoD root CA from {DoDPkeCaChainFileName}: {CreateChainStatusMessage(signerChain)}");
			}

			if (signerChain.ChainElements.Count is 0 || !string.Equals(signerChain.ChainElements[^1].Certificate.Thumbprint, rootCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidOperationException($"The DoD checksum manifest signer chain did not terminate at the root CA from {DoDPkeCaChainFileName}.");
			}
		}
	}

	/// <summary>
	/// Verifies every SHA-256 checksum listed in the signed manifest against the corresponding ZIP entry.
	/// </summary>
	private static void VerifyChecksumPayloadAgainstZipEntries(byte[] checksumPayload, IReadOnlyDictionary<string, byte[]> zipEntries)
	{
		string checksumText = Encoding.ASCII.GetString(checksumPayload);
		int verifiedFileCount = 0;
		using StringReader stringReader = new(checksumText);
		while (stringReader.ReadLine() is string line)
		{
			string trimmedLine = line.Trim();
			if (trimmedLine.Length is 0)
			{
				continue;
			}

			if (!TryParseSha256ManifestLine(trimmedLine, out string expectedHash, out string fileName))
			{
				throw new InvalidOperationException($"The signed DoD checksum manifest contains an invalid line: {trimmedLine}");
			}

			byte[] fileBytes = GetRequiredZipEntryBytes(zipEntries, fileName);
			string actualHash = Convert.ToHexString(SHA256.HashData(fileBytes));
			if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidOperationException($"The SHA-256 checksum for {fileName} does not match the signed DoD checksum manifest.");
			}

			verifiedFileCount++;
		}

		if (verifiedFileCount is 0)
		{
			throw new InvalidOperationException("The signed DoD checksum manifest did not contain any file checksums.");
		}
	}

	/// <summary>
	/// Parses a sha256sum-compatible manifest line of the form HASH whitespace filename.
	/// </summary>
	private static bool TryParseSha256ManifestLine(string line, out string expectedHash, out string fileName)
	{
		expectedHash = string.Empty;
		fileName = string.Empty;
		if (line.Length < 66)
		{
			return false;
		}

		string hashCandidate = line[..64];
		for (int index = 0; index < hashCandidate.Length; index++)
		{
			char character = hashCandidate[index];
			bool isHexCharacter = character is >= '0' and <= '9' || character is >= 'a' and <= 'f' || character is >= 'A' and <= 'F';
			if (!isHexCharacter)
			{
				return false;
			}
		}

		int fileNameStartIndex = 64;
		while (fileNameStartIndex < line.Length && char.IsWhiteSpace(line[fileNameStartIndex]))
		{
			fileNameStartIndex++;
		}

		if (fileNameStartIndex < line.Length && line[fileNameStartIndex] is '*')
		{
			fileNameStartIndex++;
		}

		while (fileNameStartIndex < line.Length && char.IsWhiteSpace(line[fileNameStartIndex]))
		{
			fileNameStartIndex++;
		}

		if (fileNameStartIndex >= line.Length)
		{
			return false;
		}

		expectedHash = hashCandidate;
		fileName = NormalizeZipEntryName(line[fileNameStartIndex..]);
		return fileName.Length is not 0;
	}

	/// <summary>
	/// Gets the signed checksum entry from the ZIP bundle.
	/// </summary>
	private static byte[] GetSignedChecksumEntryBytes(IReadOnlyDictionary<string, byte[]> zipEntries)
	{
		foreach (KeyValuePair<string, byte[]> entry in zipEntries)
		{
			if (entry.Key.EndsWith(DoDPkiBundleChecksumSignatureExtension, StringComparison.OrdinalIgnoreCase))
			{
				return entry.Value;
			}
		}

		throw new InvalidOperationException($"The DoD PKI bundle does not contain a signed {DoDPkiBundleChecksumSignatureExtension} checksum manifest.");
	}

	/// <summary>
	/// Gets a ZIP entry by exact normalized name or by leaf file name.
	/// </summary>
	private static byte[] GetRequiredZipEntryBytes(IReadOnlyDictionary<string, byte[]> zipEntries, string entryName)
	{
		string normalizedEntryName = NormalizeZipEntryName(entryName);
		if (zipEntries.TryGetValue(normalizedEntryName, out byte[]? entryBytes))
		{
			return entryBytes;
		}

		foreach (KeyValuePair<string, byte[]> entry in zipEntries)
		{
			if (string.Equals(GetZipEntryFileName(entry.Key), normalizedEntryName, StringComparison.OrdinalIgnoreCase))
			{
				return entry.Value;
			}
		}

		throw new InvalidOperationException($"The DoD PKI bundle does not contain the required entry {entryName}.");
	}

	/// <summary>
	/// Normalizes ZIP entry names for consistent manifest and archive comparisons.
	/// </summary>
	private static string NormalizeZipEntryName(string entryName)
	{
		string normalizedEntryName = entryName.Trim().Replace('\\', '/');
		while (normalizedEntryName.StartsWith("./", StringComparison.OrdinalIgnoreCase))
		{
			normalizedEntryName = normalizedEntryName[2..];
		}

		return normalizedEntryName;
	}

	/// <summary>
	/// Gets the leaf file name from a normalized ZIP entry name.
	/// </summary>
	private static string GetZipEntryFileName(string entryName)
	{
		string normalizedEntryName = NormalizeZipEntryName(entryName);
		int separatorIndex = normalizedEntryName.LastIndexOf('/');
		return separatorIndex < 0 ? normalizedEntryName : normalizedEntryName[(separatorIndex + 1)..];
	}

	/// <summary>
	/// Creates a concise chain status string for verification errors.
	/// </summary>
	private static string CreateChainStatusMessage(X509Chain chain)
	{
		StringBuilder chainStatusMessage = new();
		foreach (X509ChainStatus chainStatus in chain.ChainStatus)
		{
			if (chainStatusMessage.Length is not 0)
			{
				_ = chainStatusMessage.Append("; ");
			}

			_ = chainStatusMessage.Append(chainStatus.Status);
			_ = chainStatusMessage.Append(": ");
			_ = chainStatusMessage.Append(chainStatus.StatusInformation.Trim());
		}

		return chainStatusMessage.Length is 0 ? "No chain status details were returned." : chainStatusMessage.ToString();
	}

	/// <summary>
	/// Determines whether a ZIP entry contains a certificate format we can import from memory.
	/// </summary>
	private static bool IsSupportedCertificateBundleEntry(string entryName)
	{
		return entryName.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase)
			|| entryName.EndsWith(".cer", StringComparison.OrdinalIgnoreCase)
			|| entryName.EndsWith(".crt", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Extracts one or more DER encoded certificates from an entry in the DoD certificate bundle.
	/// </summary>
	private static List<byte[]> ExtractCertificateDerData(string entryName, byte[] certificateBytes)
	{
		List<byte[]> pemCertificateDerData = DecodePemCertificateBlocks(certificateBytes);
		if (pemCertificateDerData.Count is not 0)
		{
			return pemCertificateDerData;
		}

		byte[] normalizedBytes = DecodeFirstPemBlockIfPresent(certificateBytes);
		if (!entryName.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase))
		{
			return [normalizedBytes];
		}

		try
		{
			return ExtractCertificatesFromPkcs7(normalizedBytes, AsnEncodingRules.BER);
		}
		catch (AsnContentException)
		{
			return ExtractCertificatesFromPkcs7(normalizedBytes, AsnEncodingRules.DER);
		}
	}

	/// <summary>
	/// Decodes all PEM encoded certificate blocks from a certificate bundle entry.
	/// </summary>
	private static List<byte[]> DecodePemCertificateBlocks(byte[] certificateBytes)
	{
		string certificateText = Encoding.ASCII.GetString(certificateBytes);
		if (!certificateText.Contains(PemCertificateBeginMarker, StringComparison.OrdinalIgnoreCase))
		{
			return [];
		}

		List<byte[]> certificates = [];
		using StringReader stringReader = new(certificateText);
		StringBuilder? base64Builder = null;
		bool isInsideCertificatePemBlock = false;

		while (stringReader.ReadLine() is string line)
		{
			string trimmedLine = line.Trim();
			if (trimmedLine.StartsWith(PemCertificateBeginMarker, StringComparison.OrdinalIgnoreCase))
			{
				base64Builder = new StringBuilder();
				isInsideCertificatePemBlock = true;
				continue;
			}

			if (trimmedLine.StartsWith(PemCertificateEndMarker, StringComparison.OrdinalIgnoreCase))
			{
				if (isInsideCertificatePemBlock && base64Builder is not null)
				{
					certificates.Add(Convert.FromBase64String(base64Builder.ToString()));
				}

				base64Builder = null;
				isInsideCertificatePemBlock = false;
				continue;
			}

			if (isInsideCertificatePemBlock && base64Builder is not null)
			{
				_ = base64Builder.Append(trimmedLine);
			}
		}

		return certificates;
	}

	/// <summary>
	/// Decodes the first PEM block while leaving DER data unchanged.
	/// </summary>
	private static byte[] DecodeFirstPemBlockIfPresent(byte[] certificateBytes)
	{
		string certificateText = Encoding.ASCII.GetString(certificateBytes);
		if (!certificateText.Contains(PemBeginMarker, StringComparison.OrdinalIgnoreCase))
		{
			return certificateBytes;
		}

		StringBuilder base64Builder = new();
		using StringReader stringReader = new(certificateText);
		bool isInsidePemBlock = false;

		while (stringReader.ReadLine() is string line)
		{
			string trimmedLine = line.Trim();
			if (trimmedLine.StartsWith(PemBeginMarker, StringComparison.OrdinalIgnoreCase))
			{
				isInsidePemBlock = true;
				continue;
			}

			if (trimmedLine.StartsWith(PemEndMarker, StringComparison.OrdinalIgnoreCase))
			{
				break;
			}

			if (isInsidePemBlock)
			{
				_ = base64Builder.Append(trimmedLine);
			}
		}

		return Convert.FromBase64String(base64Builder.ToString());
	}

	/// <summary>
	/// Parses a PKCS#7 SignedData structure and returns DER encoded X.509 certificate values.
	/// </summary>
	private static List<byte[]> ExtractCertificatesFromPkcs7(byte[] pkcs7Bytes, AsnEncodingRules encodingRules)
	{
		AsnReader contentInfoReader = new(pkcs7Bytes, encodingRules);
		AsnReader contentInfoSequence = contentInfoReader.ReadSequence();
		string contentTypeObjectIdentifier = contentInfoSequence.ReadObjectIdentifier();
		if (!string.Equals(contentTypeObjectIdentifier, Pkcs7SignedDataObjectIdentifier, StringComparison.OrdinalIgnoreCase))
		{
			throw new CryptographicException("The PKCS#7 content is not a SignedData certificate bundle.");
		}

		AsnReader signedDataExplicitReader = contentInfoSequence.ReadSequence(ContextSpecificZeroAsn1Tag);
		AsnReader signedDataSequence = signedDataExplicitReader.ReadSequence();
		_ = signedDataSequence.ReadIntegerBytes();
		_ = signedDataSequence.ReadSetOf(skipSortOrderValidation: true);
		_ = signedDataSequence.ReadSequence();

		List<byte[]> certificates = [];
		if (!signedDataSequence.HasData || !signedDataSequence.PeekTag().HasSameClassAndValue(ContextSpecificZeroAsn1Tag))
		{
			return certificates;
		}

		AsnReader certificateSetReader = signedDataSequence.ReadSetOf(skipSortOrderValidation: true, ContextSpecificZeroAsn1Tag);
		while (certificateSetReader.HasData)
		{
			Asn1Tag certificateChoiceTag = certificateSetReader.PeekTag();
			ReadOnlyMemory<byte> encodedCertificateChoice = certificateSetReader.ReadEncodedValue();
			if (!certificateChoiceTag.HasSameClassAndValue(UniversalSequenceAsn1Tag))
			{
				continue;
			}

			certificates.Add(encodedCertificateChoice.ToArray());
		}

		return certificates;
	}

	/// <summary>
	/// Adds or removes the downloaded DoD CA certificates from the appropriate local machine certificate stores.
	/// </summary>
	private static DoDCertificateOperationResult ApplyDoDCertificateStoreChanges(List<X509Certificate2> certificates, bool install)
	{
		int changedCount = 0;
		int unchangedCount = 0;
		int skippedCount = 0;
		using X509Store rootStore = new(StoreName.Root, StoreLocation.LocalMachine);
		using X509Store intermediateStore = new(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
		rootStore.Open(OpenFlags.ReadWrite);
		intermediateStore.Open(OpenFlags.ReadWrite);

		foreach (X509Certificate2 certificate in CollectionsMarshal.AsSpan(certificates))
		{
			if (!IsCertificateAuthority(certificate))
			{
				skippedCount++;
				continue;
			}

			// Determine whether the certificate is self-issued and should be placed in the root store or not.
			X509Store targetStore = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) ? rootStore : intermediateStore;
			if (install)
			{
				if (StoreContainsCertificate(targetStore, certificate))
				{
					unchangedCount++;
					continue;
				}

				targetStore.Add(certificate);
				changedCount++;
				continue;
			}

			if (RemoveMatchingCertificate(targetStore, certificate))
			{
				changedCount++;
				continue;
			}

			unchangedCount++;
		}

		return new DoDCertificateOperationResult(changedCount, unchangedCount, skippedCount);
	}

	/// <summary>
	/// Checks whether a certificate is a certificate authority certificate.
	/// </summary>
	private static bool IsCertificateAuthority(X509Certificate2 certificate)
	{
		foreach (X509Extension extension in certificate.Extensions)
		{
			if (!string.Equals(extension.Oid?.Value, "2.5.29.19", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			X509BasicConstraintsExtension basicConstraints = extension as X509BasicConstraintsExtension ?? new X509BasicConstraintsExtension(extension, critical: false);
			return basicConstraints.CertificateAuthority;
		}

		return false;
	}

	/// <summary>
	/// Checks for a matching thumbprint in a certificate store.
	/// </summary>
	private static bool StoreContainsCertificate(X509Store store, X509Certificate2 certificate)
	{
		X509Certificate2Collection existingCertificates = store.Certificates;
		try
		{
			foreach (X509Certificate2 existingCertificate in existingCertificates)
			{
				if (string.Equals(existingCertificate.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}

			return false;
		}
		finally
		{
			foreach (X509Certificate2 existingCertificate in existingCertificates)
			{
				existingCertificate.Dispose();
			}
		}
	}

	/// <summary>
	/// Removes a certificate with the same thumbprint from the specified store.
	/// </summary>
	private static bool RemoveMatchingCertificate(X509Store store, X509Certificate2 certificate)
	{
		X509Certificate2Collection existingCertificates = store.Certificates;
		try
		{
			foreach (X509Certificate2 existingCertificate in existingCertificates)
			{
				if (!string.Equals(existingCertificate.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				store.Remove(existingCertificate);
				return true;
			}

			return false;
		}
		finally
		{
			foreach (X509Certificate2 existingCertificate in existingCertificates)
			{
				existingCertificate.Dispose();
			}
		}
	}

	/// <summary>
	/// Summary of the DoD certificate operation.
	/// </summary>
	internal readonly struct DoDCertificateOperationResult(int changedCount, int unchangedCount, int skippedCount)
	{
		internal int ChangedCount => changedCount;
		internal int UnchangedCount => unchangedCount;
		internal int SkippedCount => skippedCount;
	}

}
