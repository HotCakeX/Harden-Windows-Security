using System.IO;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class PolicyEditor
{
	/// <summary>
	/// Swaps the PolicyID and BasePolicyID GUIDs in an App Control for Business policy XML file for Base policies.
	/// Shouldn't be used for supplemental policies.
	/// </summary>
	/// <param name="policyIdInput"></param>
	/// <param name="policyFilePathInput"></param>
	internal static void EditGuids(string policyIdInput, FileInfo policyFilePathInput)

	{
		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(policyFilePathInput.FullName, null);

		string policyId = "{" + policyIdInput + "}";

		codeIntegrityPolicy.PolicyIDNode.InnerText = policyId;
		codeIntegrityPolicy.BasePolicyIDNode.InnerText = policyId;

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, policyFilePathInput.FullName);
	}
}
