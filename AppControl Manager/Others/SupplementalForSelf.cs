using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AppControlManager.Main;
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.Others;

internal static class SupplementalForSelf
{
	/// <summary>
	/// Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment
	/// Each Base policy should have this supplemental policy
	/// </summary>
	/// <param name="StagingArea"></param>
	internal static void Deploy(string StagingArea, string basePolicyID)
	{
		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(GlobalVars.AppControlManagerSpecialPolicyPath, null);

		#region Replace the BasePolicyID of the Supplemental Policy and reset its PolicyID which is necessary in order to have more than 1 of these supplemental policies deployed on the system

		codeIntegrityPolicy.BasePolicyIDNode.InnerText = basePolicyID;

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();

		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		codeIntegrityPolicy.PolicyIDNode.InnerText = newRandomGUIDString;

		#endregion

		string savePath = Path.Combine(StagingArea, $"{GlobalVars.AppControlManagerSpecialPolicyName}.xml");

		string cipPath = Path.Combine(StagingArea, $"{GlobalVars.AppControlManagerSpecialPolicyName}.cip");

		// Save the XML to the path as XML file
		codeIntegrityPolicy.XmlDocument.Save(savePath);

		Logger.Write($"Checking the deployment status of '{GlobalVars.AppControlManagerSpecialPolicyName}' Supplemental policy");

		// Get all the deployed supplemental policies to see if our policy is among them

		string trimmedBasePolicyID = basePolicyID.Trim('{', '}');

		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicyNoFilter = CiToolHelper.GetPolicies(false, false, true);

		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy1stFilter = [.. CurrentlyDeployedSupplementalPolicyNoFilter.Where(policy => string.Equals(policy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];

		List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy = [.. CurrentlyDeployedSupplementalPolicy1stFilter.Where(policy => string.Equals(policy.BasePolicyID, trimmedBasePolicyID, StringComparison.OrdinalIgnoreCase))];

		if (CurrentlyDeployedSupplementalPolicy.Count > 0)
		{
			Logger.Write($"Supplemental policy named {GlobalVars.AppControlManagerSpecialPolicyName} is already deployed for the base policy with the BasePolicyID {basePolicyID}, skipping its deployment.");
		}
		else
		{
			Logger.Write($"Supplemental policy named {GlobalVars.AppControlManagerSpecialPolicyName} is not deployed for the base policy with the BasePolicyID {basePolicyID}, deploying it now.");

			PolicyToCIPConverter.Convert(savePath, cipPath);

			CiToolHelper.UpdatePolicy(cipPath);
		}

	}


	/// <summary>
	/// Signs and Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment
	/// Each Base policy should have this supplemental policy
	/// </summary>
	/// <param name="StagingArea"></param>
	internal static void DeploySigned(string basePolicyID, string CertPath, string SignToolPath, string CertCN)
	{

		DirectoryInfo stagingArea = StagingArea.NewStagingArea("SignedSupplementalPolicySpecialDeployment");

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(GlobalVars.AppControlManagerSpecialPolicyPath, null);

		#region Replace the BasePolicyID of the Supplemental Policy and reset its PolicyID which is necessary in order to have more than 1 of these supplemental policies deployed on the system

		codeIntegrityPolicy.BasePolicyIDNode.InnerText = basePolicyID;

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();

		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		codeIntegrityPolicy.PolicyIDNode.InnerText = newRandomGUIDString;

		#endregion

		string savePath = Path.Combine(stagingArea.FullName, $"{GlobalVars.AppControlManagerSpecialPolicyName}.xml");

		// Save the XML to the path as XML file
		codeIntegrityPolicy.XmlDocument.Save(savePath);

		Logger.Write($"Checking the deployment status of '{GlobalVars.AppControlManagerSpecialPolicyName}' Supplemental policy");

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
				Logger.Write($"Removing unsigned Supplemental policy with the ID {item.PolicyID!} and name {item.FriendlyName} because its Signed version will be deployed.");
				CiToolHelper.RemovePolicy(item.PolicyID!);
			}
		}


		// Add the certificate's details to the policy
		_ = AddSigningDetails.Add(savePath, CertPath);

		// Remove the unsigned policy rule option from the policy
		CiRuleOptions.Set(filePath: savePath, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy]);

		// Define the path for the CIP file
		string randomString = GUIDGenerator.GenerateUniqueGUID();
		string xmlFileName = Path.GetFileName(savePath);
		string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

		string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

		// Convert the XML file to CIP
		PolicyToCIPConverter.Convert(savePath, CIPFilePath);

		// Sign the CIP
		SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

		// Rename the .p7 signed file to .cip
		File.Move(CIPp7SignedFilePath, CIPFilePath, true);

		// Deploy the signed CIP file
		CiToolHelper.UpdatePolicy(CIPFilePath);


	}

}
