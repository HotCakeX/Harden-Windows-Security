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

internal static class NewPublisherLevelRules
{

	/// <summary>
	/// Creates new Allow Publisher level rules in an XML file
	/// Each rules includes the Signers, AllowedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="xmlFilePath">The path to the XML file to be modified</param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<PublisherSignerCreator> publisherSigners)
	{

		if (publisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPublisherSignersDetectedAllowMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("PublisherSignersToAddMessage"), publisherSigners.Count, xmlFilePath));

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{

			// Create signer for each certificate details in the PublisherSigners
			// Some files are signed by multiple signers
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{

				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

				string SignerID = $"ID_SIGNER_B_{guid}";

				// Create the new Signer element

				// Create a new Signer node
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
				// Set the attributes for the new Signer node
				newSignerNode.SetAttribute("ID", SignerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
				certRootNode.SetAttribute("Type", "TBS");
				certRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(certRootNode);

				// Create the CertPublisher element and add it to the Signer element
				XmlElement certPublisherNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertPublisher", GlobalVars.SiPolicyNamespace);
				certPublisherNode.SetAttribute("Value", signerData.LeafCertName);
				_ = newSignerNode.AppendChild(certPublisherNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				// Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					// Create AllowedSigner nodes inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					newUMCIAllowedSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newUMCIAllowedSignerNode);


					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
					newCiSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					// Create AllowedSigner nodes inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					newKMCIAllowedSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newKMCIAllowedSignerNode);


					// Kernel-Mode signers don't need CI Signers
				}
			}
		}

		// Save the XML file
		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}


	/// <summary>
	/// Creates new Deny Publisher level rules in an XML file
	/// Each rules includes the Signers, DeniedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="xmlFilePath">The path to the XML file to be modified</param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<PublisherSignerCreator> publisherSigners)
	{

		if (publisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPublisherSignersDetectedDenyMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("PublisherSignersToAddMessage"), publisherSigners.Count, xmlFilePath));

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{

			// Create signer for each certificate details in the PublisherSigners
			// Some files are signed by multiple signers
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{

				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

				string SignerID = $"ID_SIGNER_B_{guid}";

				// Create the new Signer element

				// Create a new Signer node
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
				// Set the attributes for the new Signer node
				newSignerNode.SetAttribute("ID", SignerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
				certRootNode.SetAttribute("Type", "TBS");
				certRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(certRootNode);

				// Create the CertPublisher element and add it to the Signer element
				XmlElement certPublisherNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertPublisher", GlobalVars.SiPolicyNamespace);
				certPublisherNode.SetAttribute("Value", signerData.LeafCertName);
				_ = newSignerNode.AppendChild(certPublisherNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				// Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					// Create DeniedSigner nodes inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					newUMCIDeniedSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.UMCI_ProductSigners_DeniedSigners_Node.AppendChild(newUMCIDeniedSignerNode);


					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
					newCiSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					// Create DeniedSigner nodes inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					newKMCIDeniedSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.KMCI_ProductSigners_DeniedSigners_Node.AppendChild(newKMCIDeniedSignerNode);


					// Kernel-Mode signers don't need CI Signers
				}
			}
		}

		// Save the XML file
		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
