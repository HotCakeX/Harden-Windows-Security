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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class NewWHQLFilePublisherLevelRules
{

	private static readonly FrozenSet<string> WHQLTBSHashes = new string[]
	{
		// Microsoft Windows Third Party Component CA 2012
		"CEC1AFD0E310C55C1DCC601AB8E172917706AA32FB5EAF826813547FDF02DD46",

		// Microsoft Windows Third Party Component CA 2013 - Less common
		"C55EE44C6DE86FA9AC3FC90F84EF0D4A6CAD5AAC6A112047C88B997E7547AED1",

		// Microsoft Windows Third Party Component CA 2014
		"D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE"

	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	private const string EKUID = "ID_EKU_E_MSFTWHQL";
	private const string EKUValue = "010A2B0601040182370A0305";
	private const string EKUFriendlyName = "Windows Hardware Driver Verification";

	/// <summary>
	/// Creates new Allow WHQLFilePublisher level rules in the SiPolicy object
	/// Each rule includes the FileAttribs, Signers, AllowedSigners, and CiSigners(depending on kernel/user mode), EKU.
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="whqlFilePublisherSigners"> The WHQLFilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method.</param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<WHQLFilePublisherSignerCreator> whqlFilePublisherSigners)
	{
		if (whqlFilePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoWHQLFilePublisherSignersDetectedAllowMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("WHQLFilePublisherSignersToAddMessage"), whqlFilePublisherSigners.Count));

		// Ensure the lists are initialized.
		policyObj.FileRules ??= [];
		policyObj.Signers ??= [];
		policyObj.CiSigners ??= [];
		policyObj.EKUs ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure AllowedSigners exist
		umciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);
		kmciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);

		foreach (WHQLFilePublisherSignerCreator whqlFilePublisherData in CollectionsMarshal.AsSpan(whqlFilePublisherSigners))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("WHQLFilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = whqlFilePublisherData.FileVersion?.ToString()
			};

			if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.OriginalFileName))
			{
				newFileAttrib.FileName = whqlFilePublisherData.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.InternalName))
			{
				newFileAttrib.InternalName = whqlFilePublisherData.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.FileDescription))
			{
				newFileAttrib.FileDescription = whqlFilePublisherData.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.ProductName))
			{
				newFileAttrib.ProductName = whqlFilePublisherData.ProductName;
			}

			policyObj.FileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in CollectionsMarshal.AsSpan(whqlFilePublisherData.CertificateDetails))
			{
				if (!WHQLTBSHashes.Contains(signerData.IntermediateCertTBS)) continue;

				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string signerID = $"ID_SIGNER_A_{guid2}";

				if (string.IsNullOrWhiteSpace(whqlFilePublisherData.Opus))
					throw new InvalidOperationException("Cannot create WHQL signer with empty CertOEMID");

				Signer newSigner = new(
					id: signerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertEKU = [new CertEKU(id: EKUID)],
					CertOemID = new CertOemID(value: whqlFilePublisherData.Opus),
					FileAttribRef = [new FileAttribRef(ruleID: FileAttribID)]
				};

				policyObj.Signers.Add(newSigner);

				// For User-Mode files
				if (whqlFilePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciScenario.ProductSigners.AllowedSigners.AllowedSigner.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
					policyObj.CiSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (whqlFilePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciScenario.ProductSigners.AllowedSigners.AllowedSigner.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
				}
			}

			#endregion
		}

		#region Add EKU

		if (!policyObj.EKUs.Any(e => e.ID == EKUID))
		{
			policyObj.EKUs.Add(new EKU
			(
				id: EKUID,
				value: Convert.FromHexString(EKUValue),
				friendlyName: EKUFriendlyName
			));
		}

		#endregion

		return policyObj;
	}

	/// <summary>
	/// Creates new Deny WHQLFilePublisher level rules in the SiPolicy object
	/// Each rules includes the FileAttribs, Signers, DeniedSigners, and CiSigners(depending on kernel/user mode), EKU.
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="whqlFilePublisherSigners"> The WHQLFilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method.</param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateDeny(SiPolicy.SiPolicy policyObj, List<WHQLFilePublisherSignerCreator> whqlFilePublisherSigners)
	{
		if (whqlFilePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoWHQLFilePublisherSignersDetectedDenyMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("WHQLFilePublisherSignersToAddMessage"), whqlFilePublisherSigners.Count));

		// Ensure the lists are initialized.
		policyObj.FileRules ??= [];
		policyObj.Signers ??= [];
		policyObj.CiSigners ??= [];
		policyObj.EKUs ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure DeniedSigners exist
		umciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);
		kmciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);

		foreach (WHQLFilePublisherSignerCreator whqlFilePublisherData in CollectionsMarshal.AsSpan(whqlFilePublisherSigners))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("WHQLFilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = whqlFilePublisherData.FileVersion?.ToString()
			};

			if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.OriginalFileName))
			{
				newFileAttrib.FileName = whqlFilePublisherData.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.InternalName))
			{
				newFileAttrib.InternalName = whqlFilePublisherData.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.FileDescription))
			{
				newFileAttrib.FileDescription = whqlFilePublisherData.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(whqlFilePublisherData.ProductName))
			{
				newFileAttrib.ProductName = whqlFilePublisherData.ProductName;
			}

			policyObj.FileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in CollectionsMarshal.AsSpan(whqlFilePublisherData.CertificateDetails))
			{
				if (!WHQLTBSHashes.Contains(signerData.IntermediateCertTBS)) continue;

				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string signerID = $"ID_SIGNER_A_{guid2}";

				if (string.IsNullOrWhiteSpace(whqlFilePublisherData.Opus))
					throw new InvalidOperationException("Cannot create WHQL signer with empty CertOEMID");

				Signer newSigner = new(
					id: signerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertEKU = [new CertEKU(id: EKUID)],
					CertOemID = new CertOemID(value: whqlFilePublisherData.Opus),
					FileAttribRef = [new FileAttribRef(ruleID: FileAttribID)]
				};

				policyObj.Signers.Add(newSigner);

				// For User-Mode files
				if (whqlFilePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciScenario.ProductSigners.DeniedSigners.DeniedSigner.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
					policyObj.CiSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (whqlFilePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciScenario.ProductSigners.DeniedSigners.DeniedSigner.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
				}
			}

			#endregion
		}

		#region Add EKU

		if (!policyObj.EKUs.Any(e => e.ID == EKUID))
		{
			policyObj.EKUs.Add(new EKU
			(
				id: EKUID,
				value: Convert.FromHexString(EKUValue),
				friendlyName: EKUFriendlyName
			));
		}

		#endregion

		return policyObj;
	}
}
