using System;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class UpdateHvciOptions
{
	/// <summary>
	/// Sets the HVCI option to Strict or (2) in a policy XML file
	/// </summary>
	/// <param name="filePath"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Update(string filePath)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		policyObj.HvciOptionsSpecified = true;
		policyObj.HvciOptions = 2;

		// Save the modified XML document
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write($"Successfully set the HVCI in the policy file '{filePath}' to Strict.");
	}
}
