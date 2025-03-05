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
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Others;

namespace AppControlManager.SimulationMethods;

internal static class GetCertificateDetails
{
	/// <summary>
	/// A method to detect Root, Intermediate and Leaf certificates
	/// It returns a compound object that contains 2 nested objects for Intermediate and Leaf certificates
	///
	/// Old method of recognizing the certificate type:
	/// If the file's subject common name is equal to the certificate's subject common name, then it's the leaf certificate - If a certificate's subject common name is equal to its issuer common name, then it's a root certificate - otherwise it's an intermediate certificate
	/// CertType    = ($SubjectCN -eq $IssuerCN) ? 'Root' : (($SubjectCN -eq $FileSubjectCN) ? 'Leaf' : 'Intermediate')
	///
	/// </summary>
	/// <param name="completeSignatureResult"></param>
	/// <returns></returns>
	internal static List<ChainPackage> Get(List<AllFileSigners> completeSignatureResult)
	{
		// A list to hold the final result of the method
		List<ChainPackage> finalObject = [];

		// Loop over each signer of the file, in case the file has multiple separate signers
		for (int i = 0; i < completeSignatureResult.Count; i++)
		{
			// Get the current chain and SignedCms of the signer
			X509Chain currentChain = completeSignatureResult[i].Chain;
			SignedCms currentSignedCms = completeSignatureResult[i].Signer;

			// Get the number of certificates in the current chain
			uint certificatesInChainCount = (uint)currentChain.ChainElements.Count;

			switch (certificatesInChainCount)
			{
				// If the chain includes a Root, Leaf, and at least one Intermediate certificate
				case > 2:

					#region Root Certificate

					// The last certificate in the chain is the Root certificate
					X509Certificate2 currentRootCertificate = currentChain.ChainElements[^1].Certificate;

					// Create the root certificate element
					ChainElement rootCertificate = new(
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
						currentRootCertificate.NotAfter,
						currentRootCertificate.NotBefore,
						CertificateHelper.GetTBSCertificate(currentRootCertificate),
						currentRootCertificate, // Append the certificate object itself to the output object as well
						CertificateType.Root,
						currentRootCertificate // root certificate's issuer is itself
					);

					#endregion

					#region Intermediate Certificate(s)

					// List to hold the Intermediate Certificate(s) of the current chain
					List<ChainElement> intermediateCertificates = [];

					// Loop through intermediate certificates, which are all certificates in between the root and leaf certificates
					// That is why we start from 1 and end at certificatesInChainCount - 1 (excluding the root and leaf certificates)
					for (int j = 1; j < certificatesInChainCount - 1; j++)
					{
						// Get the current intermediate certificate
						X509Certificate2 cert = currentChain.ChainElements[j].Certificate;

						// Get the issuer certificate for the current intermediate certificate (which will be the next certificate in the chain)
						X509Certificate2 intermediateIssuerCertificate = currentChain.ChainElements[j + 1].Certificate;

						// Add the intermediate certificate to the list
						intermediateCertificates.Add(new ChainElement(
							CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
							CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
							cert.NotAfter,
							cert.NotBefore,
							CertificateHelper.GetTBSCertificate(cert),
							cert, // Append the certificate object itself to the output object as well
							CertificateType.Intermediate,
							intermediateIssuerCertificate
						));
					}

					#endregion

					#region Leaf Certificate

					// The first certificate in the chain is the Leaf certificate
					X509Certificate2 currentLeafCertificate = currentChain.ChainElements[0].Certificate;

					// The issuer of the leaf certificate will be the first intermediate certificate or root if none
					X509Certificate2 leafIssuerCertificate = intermediateCertificates.Count > 0
						? intermediateCertificates[0].Certificate
						: rootCertificate.Certificate;

					// Create the leaf certificate element
					ChainElement leafCertificate = new(
						CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
						CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
						currentLeafCertificate.NotAfter,
						currentLeafCertificate.NotBefore,
						CertificateHelper.GetTBSCertificate(currentLeafCertificate),
						currentLeafCertificate, // Append the certificate object itself to the output object as well
						CertificateType.Leaf,
						leafIssuerCertificate // Set issuer for the leaf certificate
					);

					#endregion

					// Add the final package with root, intermediate, and leaf certificates
					finalObject.Add(new ChainPackage(
						currentChain, // The entire current chain of the certificate
						currentSignedCms, // The entire current SignedCms object
						rootCertificate,
						[.. intermediateCertificates], // Spread the intermediate certificates list
						leafCertificate
					));

					break;

				// If the chain only includes a Root and Leaf certificate
				case 2:

					#region Root Certificate

					// The last certificate in the chain is the Root certificate
					currentRootCertificate = currentChain.ChainElements[^1].Certificate;

					// Create the root certificate element
					rootCertificate = new ChainElement(
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
						currentRootCertificate.NotAfter,
						currentRootCertificate.NotBefore,
						CertificateHelper.GetTBSCertificate(currentRootCertificate),
						currentRootCertificate, // Append the certificate object itself to the output object as well
						CertificateType.Root,
						currentRootCertificate // root certificate's issuer is itself
					);

					#endregion

					#region Leaf Certificate

					// The first certificate in the chain is the Leaf certificate
					currentLeafCertificate = currentChain.ChainElements[0].Certificate;

					// The issuer of the leaf certificate will be the root certificate
					leafIssuerCertificate = rootCertificate.Certificate;

					// Create the leaf certificate element
					leafCertificate = new ChainElement(
						CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
						CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
						currentLeafCertificate.NotAfter,
						currentLeafCertificate.NotBefore,
						CertificateHelper.GetTBSCertificate(currentLeafCertificate),
						currentLeafCertificate, // Append the certificate object itself to the output object as well
						CertificateType.Leaf,
						leafIssuerCertificate // Set issuer for the leaf certificate
					);

					#endregion

					// Add the final package with root and leaf certificates
					finalObject.Add(new ChainPackage(
						currentChain, // The entire current chain of the certificate
						currentSignedCms, // The entire current SignedCms object
						rootCertificate,
						null, // No intermediate certificates
						leafCertificate
					));

					break;

				// If the chain only includes a Root certificate
				case 1:

					#region Root Certificate

					// The only certificate in the chain is the Root certificate
					currentRootCertificate = currentChain.ChainElements[0].Certificate;

					// Create the root certificate element
					rootCertificate = new ChainElement(
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
						CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
						currentRootCertificate.NotAfter,
						currentRootCertificate.NotBefore,
						CertificateHelper.GetTBSCertificate(currentRootCertificate),
						currentRootCertificate, // Append the certificate object itself to the output object as well
						CertificateType.Root,
						currentRootCertificate // root certificate's issuer is itself
					);

					#endregion

					// Add the final package with only the root certificate
					finalObject.Add(new ChainPackage(
						currentChain, // The entire current chain of the certificate
						currentSignedCms, // The entire current SignedCms object
						rootCertificate,
						null, // No intermediate certificates
						null // No leaf certificate
					));

					break;

				default:
					break;
			}
		}

		// Return the final list of chain packages
		return finalObject;
	}
}
