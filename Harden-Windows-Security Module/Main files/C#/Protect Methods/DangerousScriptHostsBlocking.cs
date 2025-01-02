using System;
using System.Collections.Generic;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class DownloadsDefenseMeasures
{
	/// <summary>
	/// Blocks certain dangerous script hosts using App Control policy
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void DangerousScriptHostsBlocking()
	{
		if (GlobalVars.path is null)
		{
			throw new ArgumentNullException("GlobalVars.path cannot be null.");
		}

		Logger.LogMessage("Running the Dangerous Script Hosts Blocking section", LogTypeIntel.Information);

		string CIPPath = Path.Combine(GlobalVars.WorkingDir, "Dangerous-Script-Hosts-Blocking.cip");
		string XMLPath = Path.Combine(GlobalVars.path, "Resources", "Dangerous-Script-Hosts-Blocking.xml");

		// Run the CiTool and retrieve a list of base policies
		List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(SystemPolicies: false, BasePolicies: true, SupplementalPolicies: false);

		bool isFound = false;

		// loop over all policies
		foreach (CiPolicyInfo item in policies)
		{
			// find the policy with the right name
			if (string.Equals(item.FriendlyName, "Dangerous-Script-Hosts-Blocking", StringComparison.OrdinalIgnoreCase))
			{
				isFound = true;
				break;
			}
		}

		// If the Dangerous-Script-Hosts-Blocking is not deployed
		if (!isFound)
		{
			PolicyToCIPConverter.Convert(XMLPath, CIPPath);
			CiToolHelper.UpdatePolicy(CIPPath);
		}
		else
		{
			Logger.LogMessage("The Dangerous-Script-Hosts-Blocking policy is already deployed", LogTypeIntel.Information);
		}
	}
}
