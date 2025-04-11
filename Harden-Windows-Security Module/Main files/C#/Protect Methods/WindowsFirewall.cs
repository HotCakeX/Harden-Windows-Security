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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;

namespace HardenWindowsSecurity;

public static class WindowsFirewall
{
	/// <summary>
	/// Runs the Windows Firewall hardening category
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🔥 Firewall");

		Logger.LogMessage("Running the Windows Firewall category", LogTypeIntel.Information);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Firewall Policies", "registry.pol"), LGPORunner.FileType.POL);

		Logger.LogMessage("Setting the Network Location of all connections to Public", LogTypeIntel.Information);
		List<ManagementObject> AllCurrentNetworkAdapters = NetConnectionProfiles.Get();

		// Extract InterfaceIndex from each ManagementObject and convert to int array
		int[] InterfaceIndexes = [.. AllCurrentNetworkAdapters.Select(n => Convert.ToInt32(n["InterfaceIndex"], CultureInfo.InvariantCulture))];

		// Use the extracted InterfaceIndexes in the method to set all of the network locations to public
		bool ReturnResult = NetConnectionProfiles.Set(NetConnectionProfiles.NetworkCategory.Public, InterfaceIndexes, null);

		if (!ReturnResult)
		{
			Logger.LogMessage("An error occurred while setting the Network Location of all connections to Public", LogTypeIntel.ErrorInteractionRequired);
		}

		Logger.LogMessage("Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules", LogTypeIntel.Information);


		_ = PowerShellExecutor.ExecuteScript("""
Get-NetFirewallRule |
Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }
""");

	}
}
