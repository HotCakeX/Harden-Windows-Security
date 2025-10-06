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
using System.IO;
using System.Linq;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;

namespace AppControlManager.Others;

internal static class SupplementalForSelf
{

	/// <summary>
	/// Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment.
	/// Each Base policy should have this supplemental policy.
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where the policy files will be saved.</param>
	/// <param name="basePolicyID">Identifies the base policy to which the supplemental policy is associated.</param>
	internal static void Deploy(string StagingArea, string basePolicyID)
	{
		SiPolicy.SiPolicy policyObj = SwapDetails(basePolicyID);

		string savePath = Path.Combine(StagingArea, $"{GlobalVars.AppControlManagerSpecialPolicyName}.xml");

		string cipPath = Path.Combine(StagingArea, $"{GlobalVars.AppControlManagerSpecialPolicyName}.cip");

		// Save the XML to the path as XML file
		Management.SavePolicyToFile(policyObj, savePath);

		Logger.Write(string.Format(GlobalVars.GetStr("LogCheckingDeploymentStatusSupplemental"), GlobalVars.AppControlManagerSpecialPolicyName));

		// Get all the deployed supplemental policies to see if our policy is among them

		string trimmedBasePolicyID = basePolicyID.Trim('{', '}');

		// Get all of the supplemental policies deployed on the system
		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicyNoFilter = CiToolHelper.GetPolicies(false, false, true);

		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy1stFilter = [.. CurrentlyDeployedSupplementalPolicyNoFilter.Where(policy => string.Equals(policy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];

		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy = [.. CurrentlyDeployedSupplementalPolicy1stFilter.Where(policy => string.Equals(policy.BasePolicyID, trimmedBasePolicyID, StringComparison.OrdinalIgnoreCase))];

		if (CurrentlyDeployedSupplementalPolicy.Count > 0)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("LogSupplementalPolicyAlreadyDeployed"), GlobalVars.AppControlManagerSpecialPolicyName, basePolicyID));
		}
		else
		{
			Logger.Write(string.Format(GlobalVars.GetStr("LogSupplementalPolicyNotDeployedDeploying"), GlobalVars.AppControlManagerSpecialPolicyName, basePolicyID));

			Management.ConvertXMLToBinary(savePath, null, cipPath);

			CiToolHelper.UpdatePolicy(cipPath);
		}
	}

	/// <summary>
	/// Signs and Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment
	/// Each Base policy should have this supplemental policy
	/// </summary>
	/// <param name="basePolicyID">Identifies the base policy to which the supplemental policy is associated.</param>
	/// <param name="CertPath">Specifies the location of the certificate used for signing the policy.</param>
	/// <param name="CertCN">Represents the common name of the certificate for signing purposes.</param>
	internal static void DeploySigned(string basePolicyID, string CertPath, string CertCN)
	{

		DirectoryInfo stagingArea = StagingArea.NewStagingArea("SignedSupplementalPolicySpecialDeployment");

		SiPolicy.SiPolicy policyObj = SwapDetails(basePolicyID);

		string savePath = Path.Combine(stagingArea.FullName, $"{GlobalVars.AppControlManagerSpecialPolicyName}.xml");

		// Save the XML to the path as XML file
		Management.SavePolicyToFile(policyObj, savePath);

		Logger.Write(string.Format(GlobalVars.GetStr("LogCheckingDeploymentStatusSupplemental"), GlobalVars.AppControlManagerSpecialPolicyName));

		// Get all the deployed supplemental policies to see if our policy is among them

		string trimmedBasePolicyID = basePolicyID.Trim('{', '}');

		// Get all of the supplemental policies on the system
		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicyNoFilter = CiToolHelper.GetPolicies(false, false, true);

		// Filter based on their name
		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy1stFilter = [.. CurrentlyDeployedSupplementalPolicyNoFilter.Where(policy => string.Equals(policy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];

		// Only keep unsigned policies that have the same BasePolicyID as the one we are deploying
		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy = [.. CurrentlyDeployedSupplementalPolicy1stFilter.Where(policy => string.Equals(policy.BasePolicyID, trimmedBasePolicyID, StringComparison.OrdinalIgnoreCase) && !policy.IsSignedPolicy)];

		if (CurrentlyDeployedSupplementalPolicy.Count > 0)
		{
			foreach (CiPolicyInfo item in CurrentlyDeployedSupplementalPolicy)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("LogRemovingUnsignedSupplementalForSigned"), item.PolicyID!, item.FriendlyName));
				CiToolHelper.RemovePolicy(item.PolicyID!);
			}
		}

		// Add the certificate's details to the policy
		_ = AddSigningDetails.Add(savePath, CertPath);

		// Define the path for the CIP file
		string randomString = Guid.CreateVersion7().ToString("N");
		string xmlFileName = Path.GetFileName(savePath);
		string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

		// Convert the XML file to CIP
		Management.ConvertXMLToBinary(savePath, null, CIPFilePath);

		// Sign the CIP
		Signing.Main.SignCIP(CIPFilePath, CertCN);

		// Deploy the signed CIP file
		CiToolHelper.UpdatePolicy(CIPFilePath);
	}

	/// <summary>
	/// Checks whether an App Control policy is eligible to have the AppControlManager supplemental policy
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="policyFile"></param>
	/// <returns></returns>
	internal static bool IsEligible(SiPolicy.SiPolicy policyObj, string policyFile)
	{
		// Don't need to deploy it for the recommended block rules since they are only explicit Deny mode policies
		if (!string.Equals(policyObj.FriendlyName, "Microsoft Windows Recommended User Mode BlockList", StringComparison.OrdinalIgnoreCase))
		{
			if (!string.Equals(policyObj.FriendlyName, "Microsoft Windows Driver Policy", StringComparison.OrdinalIgnoreCase))
			{
				// Make sure the policy is a base policy and it doesn't have allow all rule
				if (policyObj.PolicyType is PolicyType.BasePolicy)
				{
					if (!CheckForAllowAll.Check(policyFile))
					{
						return true;
					}
				}
			}
		}

		return false;
	}

	private static SiPolicy.SiPolicy SwapDetails(string basePolicyID)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(GlobalVars.AppControlManagerSpecialPolicyPath, null);

		#region Replace the BasePolicyID of the Supplemental Policy and reset its PolicyID which is necessary in order to have more than 1 of these supplemental policies deployed on the system

		policyObj.BasePolicyID = basePolicyID;

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();

		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		policyObj.PolicyID = newRandomGUIDString;

		#endregion

		#region Change the PFN

		Allow? appControlAllowRule = (policyObj.FileRules?
		.OfType<Allow>()
		.FirstOrDefault(fa => string.Equals(fa.PackageFamilyName, "ToBeDetermined", StringComparison.OrdinalIgnoreCase))) ??
		throw new InvalidOperationException("Required allow directive absent. Supplemental binding withheld.");

		// Replace the placeholder value in the policy file with the app's real PFN.
		appControlAllowRule.PackageFamilyName = App.PFN;

		#endregion

		return policyObj;
	}

}
