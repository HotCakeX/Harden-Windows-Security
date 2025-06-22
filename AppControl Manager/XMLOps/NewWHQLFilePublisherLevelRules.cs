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
using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class NewWHQLFilePublisherLevelRules
{
	/// <summary>
	/// Microsoft Windows Third Party Component CA 2012
	/// </summary>
	private const string WHQLTBSHash = "CEC1AFD0E310C55C1DCC601AB8E172917706AA32FB5EAF826813547FDF02DD46";

	private const string EKUID = "ID_EKU_E_MSFTWHQL";
	private const string EKUValue = "010A2B0601040182370A0305";
	private const string EKUFriendlyName = "Windows Hardware Driver Verification";

	/// <summary>
	/// Creates new Allow WHQLFilePublisher level rules in an XML file
	/// Each rules includes the FileAttribs, Signers, AllowedSigners, and CiSigners(depending on kernel/user mode), EKU.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="whqlFilePublisherSigners"> The WHQLFilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method.</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<WHQLFilePublisherSignerCreator> whqlFilePublisherSigners)
	{

		if (whqlFilePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.Rizz.GetString("NoWHQLFilePublisherSignersDetectedAllowMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.Rizz.GetString("WHQLFilePublisherSignersToAddMessage"), whqlFilePublisherSigners.Count));

		foreach (WHQLFilePublisherSignerCreator whqlFilePublisherData in whqlFilePublisherSigners)
		{

			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			XmlElement newFileAttribNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttrib", GlobalVars.SiPolicyNamespace);
			newFileAttribNode.SetAttribute("ID", FileAttribID);
			newFileAttribNode.SetAttribute("FriendlyName", GlobalVars.Rizz.GetString("WHQLFilePublisherRuleTypeFriendlyName"));

			#region Creating File Attributes with automatic fallback

			if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.OriginalFileName))
			{
				newFileAttribNode.SetAttribute("FileName", whqlFilePublisherData.OriginalFileName);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.InternalName))
			{
				newFileAttribNode.SetAttribute("InternalName", whqlFilePublisherData.InternalName);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.FileDescription))
			{
				newFileAttribNode.SetAttribute("FileDescription", whqlFilePublisherData.FileDescription);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.ProductName))
			{
				newFileAttribNode.SetAttribute("ProductName", whqlFilePublisherData.ProductName);
			}

			#endregion Creating File Attributes with automatic fallback

			newFileAttribNode.SetAttribute("MinimumFileVersion", whqlFilePublisherData.FileVersion!.ToString());

			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileAttribNode);

			#endregion Creating File Attributes


			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in whqlFilePublisherData.CertificateDetails)
			{
				// Only keeping certificates with the WHQL TBS Hash, it's Intermediate
				if (!string.Equals(signerData.IntermediateCertTBS, WHQLTBSHash, StringComparison.OrdinalIgnoreCase)) continue;

				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

				string signerID = $"ID_SIGNER_A_{guid2}";

				// Create the new Signer element
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
				newSignerNode.SetAttribute("ID", signerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement newCertRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
				newCertRootNode.SetAttribute("Type", "TBS");
				newCertRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(newCertRootNode);

				// Create the CertEKU element and add it to the Signer element
				XmlElement newCertEKUNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertEKU", GlobalVars.SiPolicyNamespace);
				newCertEKUNode.SetAttribute("ID", "ID_EKU_E_MSFTWHQL");
				_ = newSignerNode.AppendChild(newCertEKUNode);

				// Create the CertOemID element and add it to the Signer element
				XmlElement newCertOemIDNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertOemID", GlobalVars.SiPolicyNamespace);
				newCertOemIDNode.SetAttribute("Value", whqlFilePublisherData.Opus);
				_ = newSignerNode.AppendChild(newCertOemIDNode);

				// Create the FileAttribRef element and add it to the Signer element
				XmlElement newFileAttribRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttribRef", GlobalVars.SiPolicyNamespace);
				newFileAttribRefNode.SetAttribute("RuleID", FileAttribID);
				_ = newSignerNode.AppendChild(newFileAttribRefNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				#region Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (whqlFilePublisherData.SiSigningScenario is 1)
				{
					// Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					newUMCIAllowedSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newUMCIAllowedSignerNode);

					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
					newCiSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (whqlFilePublisherData.SiSigningScenario is 0)
				{

					// Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					newKMCIAllowedSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newKMCIAllowedSignerNode);

					// Kernel-Mode signers don't need CI Signers
				}

				#endregion Adding signer to the Signer Scenario and CiSigners
			}

			#endregion Creating Signers
		}

		#region Add EKU

		// Create the new EKU element
		XmlElement newEKUNode = codeIntegrityPolicy.XmlDocument.CreateElement("EKU", GlobalVars.SiPolicyNamespace);
		newEKUNode.SetAttribute("ID", EKUID);
		newEKUNode.SetAttribute("Value", EKUValue);
		newEKUNode.SetAttribute("FriendlyName", EKUFriendlyName);

		// Add the EKU to the policy
		_ = codeIntegrityPolicy.EKUsNode.AppendChild(newEKUNode);

		#endregion

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}


	/// <summary>
	/// Creates new Deny WHQLFilePublisher level rules in an XML file
	/// Each rules includes the FileAttribs, Signers, DeniedSigners, and CiSigners(depending on kernel/user mode), EKU.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="whqlFilePublisherSigners"> The WHQLFilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method.</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<WHQLFilePublisherSignerCreator> whqlFilePublisherSigners)
	{

		if (whqlFilePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.Rizz.GetString("NoWHQLFilePublisherSignersDetectedDenyMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.Rizz.GetString("WHQLFilePublisherSignersToAddMessage"), whqlFilePublisherSigners.Count));

		foreach (WHQLFilePublisherSignerCreator whqlFilePublisherData in whqlFilePublisherSigners)
		{

			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			XmlElement newFileAttribNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttrib", GlobalVars.SiPolicyNamespace);
			newFileAttribNode.SetAttribute("ID", FileAttribID);
			newFileAttribNode.SetAttribute("FriendlyName", GlobalVars.Rizz.GetString("WHQLFilePublisherRuleTypeFriendlyName"));

			#region Creating File Attributes with automatic fallback

			if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.OriginalFileName))
			{
				newFileAttribNode.SetAttribute("FileName", whqlFilePublisherData.OriginalFileName);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.InternalName))
			{
				newFileAttribNode.SetAttribute("InternalName", whqlFilePublisherData.InternalName);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.FileDescription))
			{
				newFileAttribNode.SetAttribute("FileDescription", whqlFilePublisherData.FileDescription);
			}

			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.ProductName))
			{
				newFileAttribNode.SetAttribute("ProductName", whqlFilePublisherData.ProductName);
			}

			#endregion Creating File Attributes with automatic fallback

			newFileAttribNode.SetAttribute("MinimumFileVersion", whqlFilePublisherData.FileVersion!.ToString());

			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileAttribNode);

			#endregion Creating File Attributes


			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in whqlFilePublisherData.CertificateDetails)
			{
				// Only keeping certificates with the WHQL TBS Hash, it's Intermediate
				if (!string.Equals(signerData.IntermediateCertTBS, WHQLTBSHash, StringComparison.OrdinalIgnoreCase)) continue;

				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

				string signerID = $"ID_SIGNER_A_{guid2}";

				// Create the new Signer element
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
				newSignerNode.SetAttribute("ID", signerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement newCertRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
				newCertRootNode.SetAttribute("Type", "TBS");
				newCertRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(newCertRootNode);

				// Create the CertEKU element and add it to the Signer element
				XmlElement newCertEKUNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertEKU", GlobalVars.SiPolicyNamespace);
				newCertEKUNode.SetAttribute("ID", "ID_EKU_E_MSFTWHQL");
				_ = newSignerNode.AppendChild(newCertEKUNode);

				// Create the CertOemID element and add it to the Signer element
				XmlElement newCertOemIDNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertOemID", GlobalVars.SiPolicyNamespace);
				newCertOemIDNode.SetAttribute("Value", whqlFilePublisherData.Opus);
				_ = newSignerNode.AppendChild(newCertOemIDNode);

				// Create the FileAttribRef element and add it to the Signer element
				XmlElement newFileAttribRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttribRef", GlobalVars.SiPolicyNamespace);
				newFileAttribRefNode.SetAttribute("RuleID", FileAttribID);
				_ = newSignerNode.AppendChild(newFileAttribRefNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				#region Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (whqlFilePublisherData.SiSigningScenario is 1)
				{
					// Create Denied Signers inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					newUMCIDeniedSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.UMCI_ProductSigners_DeniedSigners_Node.AppendChild(newUMCIDeniedSignerNode);

					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
					newCiSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (whqlFilePublisherData.SiSigningScenario is 0)
				{
					// Create Denied Signers inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					newKMCIDeniedSignerNode.SetAttribute("SignerId", signerID);
					_ = codeIntegrityPolicy.KMCI_ProductSigners_DeniedSigners_Node.AppendChild(newKMCIDeniedSignerNode);


					// Kernel-Mode signers don't need CI Signers
				}

				#endregion Adding signer to the Signer Scenario and CiSigners
			}

			#endregion Creating Signers
		}

		#region Add EKU

		// Create the new EKU element
		XmlElement newEKUNode = codeIntegrityPolicy.XmlDocument.CreateElement("EKU", GlobalVars.SiPolicyNamespace);
		newEKUNode.SetAttribute("ID", EKUID);
		newEKUNode.SetAttribute("Value", EKUValue);
		newEKUNode.SetAttribute("FriendlyName", EKUFriendlyName);

		// Add the EKU to the policy
		_ = codeIntegrityPolicy.EKUsNode.AppendChild(newEKUNode);

		#endregion

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
