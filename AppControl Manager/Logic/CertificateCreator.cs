using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Logging;

namespace AppControlManager;

internal static class CertificateGenerator
{

	/// <summary>
	/// Build a self-signed on-device certificate for the purpose of App Control policy signing
	/// Use certutil -dump -v '.\codesign.cer' to view the certificate properties, such as encoding of the certificate fields like the subject
	/// </summary>
	/// <param name="CommonName"></param>
	/// <param name="Password"></param>
	internal static X509Certificate2 BuildAppControlCertificate(string CommonName, string Password, int validity, int keySize)
	{
		// Paths for .cer and .pfx files
		string cerFilePath = Path.Combine(GlobalVars.UserConfigDir, $"{CommonName}.cer");
		string pfxFilePath = Path.Combine(GlobalVars.UserConfigDir, $"{CommonName}.pfx");

		Logger.Write($"Checking if a certificate with the common name '{CommonName}' already exists in the personal user store.");

		// Check see if there are any certificates in the personal store of User certificates with the selected Common Name
		List<X509Certificate2> possibleExistingCerts = GetCertificatesFromPersonalStore(CommonName);

		if (possibleExistingCerts.Count > 0)
		{
			Logger.Write($"{possibleExistingCerts.Count} certificates with the common name '{CommonName}' already exist on the system. Removing them");

			using X509Store store = new("My", StoreLocation.CurrentUser);
			store.Open(OpenFlags.MaxAllowed | OpenFlags.IncludeArchived | OpenFlags.OpenExistingOnly);

			foreach (X509Certificate2 cert in possibleExistingCerts)
			{
				store.Remove(cert);
			}

			store.Close();
		}

		X509Certificate2 generatedCertificate = GenerateSelfSignedCertificate(
			subjectName: CommonName,
			validityInYears: validity,
			keySize: keySize,
			hashAlgorithm: HashAlgorithmName.SHA512,
			storeLocation: CertificateStoreLocation.User,
			cerExportFilePath: cerFilePath,
			friendlyName: CommonName,
			pfxExportFilePath: pfxFilePath,
			pfxPassword: Password,
			UserProtectedPrivateKey: true,
			ExportablePrivateKey: true);

		// Save the newly created certificate's details in the user config JSON file
		_ = UserConfiguration.Set(
			CertificatePath: cerFilePath,
			CertificateCommonName: CommonName
			);


		return generatedCertificate;
	}



	// Enum representing the applicable certificate stores
	internal enum CertificateStoreLocation
	{
		User,
		Machine
	}

	internal static X509Certificate2 GenerateSelfSignedCertificate(
		string subjectName,
		int validityInYears,
		int keySize,
		HashAlgorithmName hashAlgorithm,
		CertificateStoreLocation? storeLocation,
		bool UserProtectedPrivateKey,
		bool ExportablePrivateKey,
		string? cerExportFilePath = null,
		string? friendlyName = null,
		string? pfxExportFilePath = null,
		string? pfxPassword = null)
	{
		X500DistinguishedName distinguishedName = new($"CN={subjectName}");

		using RSA rsa = RSA.Create(keySize);

		CertificateRequest request = new(distinguishedName, rsa, hashAlgorithm, RSASignaturePadding.Pkcs1);

		// adds basic constraints to the certificate request to make it a non-CA and end entity certificate.
		request.CertificateExtensions.Add(
			new X509BasicConstraintsExtension(false, false, 0, true));

		// Add key usage
		request.CertificateExtensions.Add(
			new X509KeyUsageExtension(
				X509KeyUsageFlags.DigitalSignature,
				true));



		// Add subject key identifier
		// Its raw data which is a byte array will always start with 4, 20
		// 4: This indicates the ASN.1 type is an OCTET STRING.
		// 20: The length of the OCTET STRING is 20 bytes.
		// Remaining bytes are generated randomly for each certificate

		// adds "[1]Application Certificate Policy:Policy Identifier=Code Signing" as the value for Application Policies extension. The certificate made in CA role in Windows Server (using Code Signing template) also adds this extension.
		request.CertificateExtensions.Add(
			new X509SubjectKeyIdentifierExtension(request.PublicKey, false));



		// Add enhanced key usage
		// Code Signing
		request.CertificateExtensions.Add(
			new X509EnhancedKeyUsageExtension(
				[new Oid("1.3.6.1.5.5.7.3.3")],
				false)
			);

		// Add custom extension for "Application Policies"
		// Application Policies OID
		Oid appPoliciesOid = new("1.3.6.1.4.1.311.21.10");
		// this must be set as specified and not randomly generated
		byte[] appPoliciesValue = [48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 3];
		X509Extension appPoliciesExtension = new(appPoliciesOid, appPoliciesValue, false);
		request.CertificateExtensions.Add(appPoliciesExtension);


		DateTimeOffset notBefore = DateTimeOffset.UtcNow;
		DateTimeOffset notAfter = notBefore.AddYears(validityInYears);

		// Generate the certificate
		using X509Certificate2 cert = request.CreateSelfSigned(notBefore, notAfter);


		// Export the certificate for .PFX file as Byte Array
		byte[] certData = cert.Export(X509ContentType.Pfx, pfxPassword);

		// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader.loadpkcs12
		// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keystorageflags

		X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.PersistKeySet;

		if (UserProtectedPrivateKey)
		{
			keyStorageFlags |= X509KeyStorageFlags.UserProtected;
		}

		if (ExportablePrivateKey)
		{
			keyStorageFlags |= X509KeyStorageFlags.Exportable;
		}

		X509Certificate2 generatedCert = X509CertificateLoader.LoadPkcs12(certData, pfxPassword, keyStorageFlags);

		// Set the friendly name if provided
		if (!string.IsNullOrEmpty(friendlyName))
		{
			generatedCert.FriendlyName = friendlyName;
		}

		// If path to export .cer file is provided, export the certificate (public key only)
		if (!string.IsNullOrEmpty(cerExportFilePath))
		{
			// Export as DER-encoded X.509 .cer file
			byte[] cerData = cert.Export(X509ContentType.Cert);
			File.WriteAllBytes(cerExportFilePath, cerData);
		}

		// If path to export .pfx file is provided, export the certificate (public + private keys)
		if (!string.IsNullOrEmpty(pfxExportFilePath))
		{
			File.WriteAllBytes(pfxExportFilePath, certData);
		}

		if (storeLocation is not null)
		{
			// Store the certificate in the specified certificate store
			StoreCertificateInStore(generatedCert, storeLocation, false);
		}

		return generatedCert;
	}



	/// <summary>
	/// Stores the certificate in one of the pre-defined certificate stores
	/// </summary>
	/// <param name="cert"></param>
	/// <param name="storeLocation"></param>
	internal static void StoreCertificateInStore(X509Certificate2 cert, CertificateStoreLocation? storeLocation, bool publicKeyOnly)
	{
		// Choose the store based on the user selection
		StoreName storeName = storeLocation == CertificateStoreLocation.User ? StoreName.My : StoreName.Root;
		StoreLocation location = storeLocation == CertificateStoreLocation.User ? StoreLocation.CurrentUser : StoreLocation.LocalMachine;


		if (publicKeyOnly)
		{
			// Export the certificate as a public key only (DER-encoded)
			byte[] publicKeyData = cert.Export(X509ContentType.Cert);

			// Reload the certificate from the exported public key data and replace the incoming data to eliminate the private key
			// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader.loadcertificate
			cert = X509CertificateLoader.LoadCertificate(publicKeyData);
		}


		using X509Store store = new(storeName, location);
		store.Open(OpenFlags.ReadWrite);
		store.Add(cert);
		store.Close();
	}



	/// <summary>
	/// Searches through all the relevant certificate stores for any certificate with a given Subject Common Name
	/// And deletes all of the detected instances
	/// </summary>
	/// <param name="subjectName"></param>
	internal static void DeleteCertificateByCN(string subjectName)
	{
		// Search through both user and machine certificate stores
		DeleteCertificateFromAllStores(subjectName, StoreLocation.CurrentUser);
		DeleteCertificateFromAllStores(subjectName, StoreLocation.LocalMachine);
	}


	/// <summary>
	/// Deletes the certificate
	/// </summary>
	/// <param name="subjectName"></param>
	/// <param name="storeLocation"></param>
	private static void DeleteCertificateFromAllStores(string subjectName, StoreLocation storeLocation)
	{
		// List of all known certificate store names
		string[] allStoreNames =
		[
			"My", // Personal / Certificates
                "Root", // Trusted Root Certification Authorities / Certificates
                "CA", // Intermediate Certification Authorities / Certificates
                "AuthRoot", // Third-Party Root Certification Authorities / Certificates
                "TrustedPeople", // Trusted People
                "TrustedPublisher" // Trusted Publishers
            ];


		// Iterate through all specified store names
		foreach (string storeName in allStoreNames)
		{

			using X509Store store = new(storeName, storeLocation);
			// MaxAllowed is necessary otherwise we'd get access denied error
			store.Open(OpenFlags.MaxAllowed | OpenFlags.IncludeArchived | OpenFlags.OpenExistingOnly);

			// Loop through the certificates in the store and find the one with the matching CN
			foreach (X509Certificate2 cert in store.Certificates)
			{
				if (cert.SubjectName.Name.Contains($"CN={subjectName}", StringComparison.OrdinalIgnoreCase))
				{
					// Certificate found with the matching CN, so delete it
					store.Remove(cert);
					Logger.Write($"Deleted certificate with CN: {subjectName} from store: {storeName}");
				}
			}

			store.Close();

		}
	}


	internal static List<X509Certificate2> GetCertificatesFromPersonalStore(string subjectName)
	{
		List<X509Certificate2> matchingCertificates = [];

		using X509Store store = new("My", StoreLocation.CurrentUser);
		store.Open(OpenFlags.MaxAllowed | OpenFlags.IncludeArchived | OpenFlags.OpenExistingOnly);

		// Loop through certificates in the "My" store
		foreach (X509Certificate2 cert in store.Certificates)
		{
			if (cert.SubjectName.Name.Contains($"CN={subjectName}", StringComparison.OrdinalIgnoreCase))
			{
				// Add certificate to the list if it matches the CN
				matchingCertificates.Add(cert);
			}
		}

		store.Close();

		return matchingCertificates;
	}



}
