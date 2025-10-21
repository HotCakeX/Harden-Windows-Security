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
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class NewCertificateSignerRules
{
	/// <summary>
	/// Creates new Signer rules for Certificates, in the XML file
	/// The level is Pca/Root/Leaf certificate, meaning there is no certificate publisher mentioned
	/// Only Certificate TBS and its name is used.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="signerData"></param>
	internal static void CreateAllow(string xmlFilePath, List<CertificateSignerCreator> signerData)
	{

		if (signerData.Count is 0)
		{
			Logger.Write($"no Certificate rules detected to create allow rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		foreach (CertificateSignerCreator signer in signerData)
		{
			// Create a unique ID for the Signer element
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			string SignerID = $"ID_SIGNER_R_{guid}";

			// Create the new Signer element
			XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
			newSignerNode.SetAttribute("ID", SignerID);
			newSignerNode.SetAttribute("Name", signer.SignerName);

			// Create the CertRoot element and add it to the Signer element
			XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
			certRootNode.SetAttribute("Type", "TBS");
			certRootNode.SetAttribute("Value", signer.TBS);

			_ = newSignerNode.AppendChild(certRootNode);

			// Add the new Signer element to the Signers node
			_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


			// For User-Mode files
			if (signer.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				// Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement newAllowedSigner = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
				newAllowedSigner.SetAttribute("SignerId", SignerID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newAllowedSigner);


				// Create a CI Signer for the User Mode Signer
				XmlElement newCiSigner = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
				newCiSigner.SetAttribute("SignerId", SignerID);
				_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSigner);
			}

			// For Kernel-Mode files
			else if (signer.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{
				// Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement newAllowedSigner = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
				newAllowedSigner.SetAttribute("SignerId", SignerID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newAllowedSigner);

				// Kernel-Mode signers don't need CI Signers
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}
}
