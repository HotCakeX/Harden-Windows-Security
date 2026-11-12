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
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// Creates, trusts and enumerates the TLS server certificates used by the local DNS-over-HTTPS server.
/// </summary>
internal static class DnsOverHttpsCertificateManager
{
	private const int RsaKeySize = 3072;
	private const int ValidityInYears = 5;
	private const string FriendlyNamePrefix = "Smart DNS DoH - ";
	private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

	/// <summary>
	/// Generated certificates are stored in the Local Machine stores. The DNS page in the app always runs elevated, so no trust
	/// confirmation dialog is shown, and the Windows DNS client (which runs as a system service and uses the machine
	/// trust store) trusts the certificate when this device itself is pointed at the local DoH server.
	/// </summary>
	private const StoreLocation GeneratedCertificateStoreLocation = StoreLocation.LocalMachine;

	internal static CertificateCreationResult CreateAndTrust(string identity, int listenerPort)
	{
		if (!TryNormalizeIdentity(identity, out string normalizedIdentity, out IPAddress? ipAddress))
		{
			throw new ArgumentException("The certificate identity must be a valid DNS hostname or IP address.", nameof(identity));
		}
		X500DistinguishedNameBuilder distinguishedNameBuilder = new();
		distinguishedNameBuilder.AddCommonName(normalizedIdentity);
		X500DistinguishedName distinguishedName = distinguishedNameBuilder.Build();
		using RSA rsa = RSA.Create(RsaKeySize);
		CertificateRequest request = new(
			distinguishedName,
			rsa,
			HashAlgorithmName.SHA256,
			RSASignaturePadding.Pkcs1);
		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(
			X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
			true));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
		OidCollection enhancedKeyUsages = new()
		{
			new Oid(ServerAuthenticationOid)
		};
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, false));
		SubjectAlternativeNameBuilder subjectAlternativeNameBuilder = new();
		if (ipAddress is null)
		{
			subjectAlternativeNameBuilder.AddDnsName(normalizedIdentity);
		}
		else
		{
			subjectAlternativeNameBuilder.AddIpAddress(ipAddress);
		}
		request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build(false));
		DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
		DateTimeOffset notAfter = notBefore.AddYears(ValidityInYears);
		using X509Certificate2 createdCertificate = request.CreateSelfSigned(notBefore, notAfter);
		byte[] pkcs12Data = createdCertificate.Export(X509ContentType.Pfx, string.Empty);
		using X509Certificate2 persistedCertificate = X509CertificateLoader.LoadPkcs12(
			pkcs12Data,
			string.Empty,
			X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
		persistedCertificate.FriendlyName = $"{FriendlyNamePrefix}{normalizedIdentity}";
		using X509Store personalStore = new(StoreName.My, GeneratedCertificateStoreLocation);
		personalStore.Open(OpenFlags.ReadWrite);
		RemovePreviousGeneratedCertificates(personalStore, normalizedIdentity);
		personalStore.Add(persistedCertificate);
		using X509Certificate2 publicCertificate = X509CertificateLoader.LoadCertificate(
			persistedCertificate.Export(X509ContentType.Cert));
		publicCertificate.FriendlyName = $"{FriendlyNamePrefix}{normalizedIdentity}";
		using X509Store trustedRootStore = new(StoreName.Root, GeneratedCertificateStoreLocation);
		trustedRootStore.Open(OpenFlags.ReadWrite);
		RemovePreviousGeneratedCertificates(trustedRootStore, normalizedIdentity);
		trustedRootStore.Add(publicCertificate);
		string httpsTemplate = BuildHttpsTemplate(normalizedIdentity, listenerPort);
		return new CertificateCreationResult(
			httpsTemplate,
			persistedCertificate.Thumbprint,
			GeneratedCertificateStoreLocation,
			notAfter);
	}

	/// <summary>
	/// Removes only the selected thumbprint from its personal store. A matching root copy is
	/// removed only when the personal certificate carries this app's generated-certificate marker.
	/// Private keys are deliberately retained because other certificates may share them.
	/// </summary>
	internal static void DeleteCertificate(DohCertificateOption option)
	{
		if (option.StoreLocation is not (StoreLocation.LocalMachine or StoreLocation.CurrentUser) ||
			string.IsNullOrWhiteSpace(option.Thumbprint))
		{
			throw new ArgumentException("The certificate store or thumbprint is invalid.", nameof(option));
		}

		using X509Store personalStore = new(StoreName.My, option.StoreLocation);
		personalStore.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
		X509Certificate2Collection certificates = personalStore.Certificates;
		try
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				if (!string.Equals(certificate.Thumbprint, option.Thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				if (certificate.FriendlyName.StartsWith(FriendlyNamePrefix, StringComparison.OrdinalIgnoreCase))
				{
					// Remove trust first. If it fails, leave the personal certificate available for retry.
					RemoveCertificateFromStore(StoreName.Root, option.StoreLocation, option.Thumbprint);
				}
				personalStore.Remove(certificate);
			}
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
	/// Removes exact thumbprint matches and disposes every certificate returned by the store.
	/// An already absent certificate is treated as successfully removed.
	/// </summary>
	private static void RemoveCertificateFromStore(StoreName storeName, StoreLocation location, string thumbprint)
	{
		using X509Store store = new(storeName, location);
		store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
		X509Certificate2Collection certificates = store.Certificates;
		try
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				if (string.Equals(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					store.Remove(certificate);
				}
			}
		}
		finally
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				certificate.Dispose();
			}
		}
	}

	internal static List<DohCertificateOption> GetAvailableCertificates()
	{
		List<DohCertificateOption> certificates = [];
		AddAvailableCertificates(certificates, StoreLocation.LocalMachine);
		AddAvailableCertificates(certificates, StoreLocation.CurrentUser);
		certificates.Sort(static (left, right) => StringComparer.OrdinalIgnoreCase.Compare(left.DisplayName, right.DisplayName));
		return certificates;
	}

	internal static string BuildHttpsTemplate(string identity, int listenerPort)
	{
		if (!TryNormalizeIdentity(identity, out string normalizedIdentity, out IPAddress? ipAddress) || listenerPort is < 1 or > 65535)
		{
			return string.Empty;
		}
		string uriHost = ipAddress?.AddressFamily == AddressFamily.InterNetworkV6
			? $"[{normalizedIdentity}]"
			: normalizedIdentity;
		string port = listenerPort == 443 ? string.Empty : $":{listenerPort}";
		return $"https://{uriHost}{port}/dns-query";
	}

	internal static bool IsValidIdentity(string identity) => TryNormalizeIdentity(identity, out _, out _);

	private static void AddAvailableCertificates(List<DohCertificateOption> certificates, StoreLocation storeLocation)
	{
		using X509Store store = new(StoreName.My, storeLocation);
		try
		{
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
		}
		catch (CryptographicException)
		{
			return;
		}
		DateTime now = DateTime.Now;
		foreach (X509Certificate2 certificate in store.Certificates)
		{
			using (certificate)
			{
				if (!certificate.HasPrivateKey || now < certificate.NotBefore || now > certificate.NotAfter || !SupportsServerAuthentication(certificate))
				{
					continue;
				}
				string simpleName = certificate.GetNameInfo(X509NameType.SimpleName, false);
				string subject = string.IsNullOrWhiteSpace(simpleName) ? certificate.Subject : simpleName;
				certificates.Add(new DohCertificateOption(
					certificate.Thumbprint,
					storeLocation,
					subject,
					certificate.NotAfter));
			}
		}
	}

	internal static bool SupportsServerAuthentication(X509Certificate2 certificate)
	{
		foreach (X509Extension extension in certificate.Extensions)
		{
			if (extension is not X509EnhancedKeyUsageExtension enhancedKeyUsage)
			{
				continue;
			}
			foreach (Oid usage in enhancedKeyUsage.EnhancedKeyUsages)
			{
				if (string.Equals(usage.Value, ServerAuthenticationOid, StringComparison.Ordinal))
				{
					return true;
				}
			}
			return false;
		}
		return true;
	}

	private static bool TryNormalizeIdentity(string identity, out string normalizedIdentity, out IPAddress? ipAddress)
	{
		string trimmedIdentity = identity.Trim();
		if (IPAddress.TryParse(trimmedIdentity, out ipAddress))
		{
			normalizedIdentity = ipAddress.ToString();
			return true;
		}
		if (Uri.CheckHostName(trimmedIdentity) == UriHostNameType.Dns)
		{
			normalizedIdentity = DnsMessage.ToLowerCaseName(trimmedIdentity);
			return true;
		}
		normalizedIdentity = string.Empty;
		ipAddress = null;
		return false;
	}

	private static void RemovePreviousGeneratedCertificates(X509Store store, string identity)
	{
		string expectedFriendlyName = $"{FriendlyNamePrefix}{identity}";
		List<X509Certificate2> certificatesToRemove = [];
		foreach (X509Certificate2 certificate in store.Certificates)
		{
			if (string.Equals(certificate.FriendlyName, expectedFriendlyName, StringComparison.OrdinalIgnoreCase))
			{
				certificatesToRemove.Add(certificate);
			}
			else
			{
				certificate.Dispose();
			}
		}
		foreach (X509Certificate2 certificate in certificatesToRemove)
		{
			using (certificate)
			{
				store.Remove(certificate);
			}
		}
	}

	internal readonly record struct CertificateCreationResult(
		string HttpsTemplate,
		string Thumbprint,
		StoreLocation StoreLocation,
		DateTimeOffset NotAfter);
}

/// <summary>
/// A certificate with a private key that can be used by the DoH server.
/// </summary>
internal sealed record DohCertificateOption(string Thumbprint, StoreLocation StoreLocation, string Subject, DateTime NotAfter)
{
	internal string DisplayName => $"{Subject} | {StoreLocation} | {NotAfter:d}";
	public override string ToString() => DisplayName;
}
