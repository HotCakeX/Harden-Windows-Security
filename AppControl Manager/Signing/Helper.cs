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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Others;

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
			Logger.Write(GlobalVars.Rizz.GetString("SubjectNameFragmentEmpty"));
			return null;
		}

		// Search in the personal stores of current user and local machine
		X509Store[] storesToSearch = [
			new(StoreName.My, StoreLocation.CurrentUser),
			new(StoreName.My, StoreLocation.LocalMachine)
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
					Logger.Write(string.Format(GlobalVars.Rizz.GetString("NoCertificatesFoundInStore"), store.Location, store.Name));
					continue;
				}

				Logger.Write(string.Format(GlobalVars.Rizz.GetString("SearchingCertificatesInStore"), certificates.Count, store.Location, store.Name, subjectNameFragment, targetCN));

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

					Logger.Write(string.Format(GlobalVars.Rizz.GetString("FoundCertificateWithMatchingSubject"), cert.Subject, cert.Thumbprint));
					Logger.Write(string.Format(GlobalVars.Rizz.GetString("SignatureAlgorithmInfo"), cert.SignatureAlgorithm.FriendlyName, cert.SignatureAlgorithm.Value));

					bool isCodeSigning = false;
					foreach (X509Extension extension in cert.Extensions)
					{
						if (string.Equals(extension.Oid?.FriendlyName, "Enhanced Key Usage", StringComparison.OrdinalIgnoreCase))
						{
							X509EnhancedKeyUsageExtension eku = (X509EnhancedKeyUsageExtension)extension;
							foreach (Oid oid in eku.EnhancedKeyUsages)
							{
								if (oid.Value == Structure.CodeSigningOID)
								{
									isCodeSigning = true;
									Logger.Write(GlobalVars.Rizz.GetString("CertificateHasCodeSigningEKU"));
									break;
								}
							}
						}
						if (isCodeSigning) break;
					}

					if (!isCodeSigning) Logger.Write(GlobalVars.Rizz.GetString("CertificateDoesNotHaveCodeSigningEKU"));

					if (cert.HasPrivateKey && isCodeSigning)
					{
						Logger.Write(string.Format(GlobalVars.Rizz.GetString("SuitableCodeSigningCertificateFound"), cert.Subject, store.Location, store.Name, cert.Thumbprint));
						return cert;
					}
				}
			}
			catch (CryptographicException ex)
			{
				Logger.Write(string.Format(GlobalVars.Rizz.GetString("CryptographicErrorAccessingStore"), store?.Name, store?.Location, ex.Message));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.Rizz.GetString("GeneralErrorAccessingStore"), store?.Name, store?.Location, ex.Message));
			}
			finally
			{
				store?.Close();
			}
		}

		Logger.Write(string.Format(GlobalVars.Rizz.GetString("NoSuitableCodeSigningCertificateFound"), subjectNameFragment));
		return null;
	}
}
