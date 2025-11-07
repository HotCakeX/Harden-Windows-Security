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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Signing;

internal static class Helper
{
	/// <summary>
	/// Find a certificate via its common name.
	/// </summary>
	/// <param name="subjectNameFragment"></param>
	/// <returns></returns>
	internal static X509Certificate2? FindCertificateBySubjectName(string subjectNameFragment)
	{
		if (string.IsNullOrWhiteSpace(subjectNameFragment))
		{
			Logger.Write(GlobalVars.GetStr("SubjectNameFragmentEmpty"));
			return null;
		}

		using X509Store currentUserStore = new(StoreName.My, StoreLocation.CurrentUser);
		using X509Store localMachineStore = new(StoreName.My, StoreLocation.LocalMachine);

		// Search in the personal stores of current user and local machine
		X509Store[] storesToSearch = [
			currentUserStore,
			localMachineStore
		];

		// Normalize the input CN
		string targetCN;
		if (!subjectNameFragment.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
		{
			targetCN = $"CN={subjectNameFragment}";
		}
		else
		{
			targetCN = subjectNameFragment;
		}

		foreach (X509Store storeInstance in storesToSearch)
		{
			X509Store? store = null;
			try
			{
				store = storeInstance;
				store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

				X509Certificate2Collection certificates = store.Certificates;
				if (certificates.Count == 0)
				{
					Logger.Write(string.Format(GlobalVars.GetStr("NoCertificatesFoundInStore"), store.Location, store.Name));
					continue;
				}

				Logger.Write(string.Format(GlobalVars.GetStr("SearchingCertificatesInStore"), certificates.Count, store.Location, store.Name, subjectNameFragment, targetCN));

				foreach (X509Certificate2 cert in certificates)
				{
					bool subjectMatch = false;
					if (cert.Subject.Equals(targetCN, StringComparison.OrdinalIgnoreCase))
					{
						subjectMatch = true;
					}
					else if (!subjectNameFragment.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) &&
							 cert.GetNameInfo(X509NameType.SimpleName, false).Equals(subjectNameFragment, StringComparison.OrdinalIgnoreCase) &&
							 cert.Subject.Contains(targetCN, StringComparison.OrdinalIgnoreCase))
					{
						subjectMatch = true;
					}
					else if (cert.Subject.Contains(subjectNameFragment, StringComparison.OrdinalIgnoreCase))
					{
						subjectMatch = true;
					}

					if (!subjectMatch) continue;

					Logger.Write(string.Format(GlobalVars.GetStr("FoundCertificateWithMatchingSubject"), cert.Subject, cert.Thumbprint));
					Logger.Write(string.Format(GlobalVars.GetStr("SignatureAlgorithmInfo"), cert.SignatureAlgorithm.FriendlyName, cert.SignatureAlgorithm.Value));

					bool isCodeSigning = false;
					foreach (X509Extension extension in cert.Extensions)
					{
						if (extension is X509EnhancedKeyUsageExtension eku)
						{
							foreach (Oid oid in eku.EnhancedKeyUsages)
							{
								if (string.Equals(oid.Value, Structure.CodeSigningOID, StringComparison.OrdinalIgnoreCase))
								{
									isCodeSigning = true;
									Logger.Write(GlobalVars.GetStr("CertificateHasCodeSigningEKU"));
									break;
								}
							}
						}

						if (isCodeSigning) break;
					}

					if (!isCodeSigning) Logger.Write(GlobalVars.GetStr("CertificateDoesNotHaveCodeSigningEKU"));

					if (cert.HasPrivateKey && isCodeSigning)
					{
						Logger.Write(string.Format(GlobalVars.GetStr("SuitableCodeSigningCertificateFound"), cert.Subject, store.Location, store.Name, cert.Thumbprint));
						return cert;
					}
				}
			}
			catch (CryptographicException ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("CryptographicErrorAccessingStore"), store?.Name, store?.Location, ex.Message));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("GeneralErrorAccessingStore"), store?.Name, store?.Location, ex.Message));
			}
			finally
			{
				store?.Close();
			}
		}

		Logger.Write(string.Format(GlobalVars.GetStr("NoSuitableCodeSigningCertificateFound"), subjectNameFragment));
		return null;
	}
}
