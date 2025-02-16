using System;
using System.Collections.Generic;

namespace AppControlManager.Others;

internal static class RemoveUserModeSS
{
	/// <summary>
	/// Removes the User-mode signing scenario block completely
	/// </summary>
	/// <param name="filePath">The path to the XML file</param>
	/// <exception cref="Exception"></exception>
	internal static void Remove(string filePath)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		// Convert the array to a list for easy manipulation
		List<SiPolicy.SigningScenario> signingScenarios = [.. policyObj.SigningScenarios];

		// Remove any signing scenario with the ID 12 representing User-Mode
		foreach (SiPolicy.SigningScenario scenario in signingScenarios)
		{
			if (string.Equals(scenario.ID, "12", StringComparison.OrdinalIgnoreCase))
			{
				_ = signingScenarios.Remove(scenario);
			}
		}

		// Convert the list back to array in order to save it in the policyObj
		policyObj.SigningScenarios = [.. signingScenarios];

		// Save the changes back to the file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);
	}
}
