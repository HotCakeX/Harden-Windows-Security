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

namespace AppControlManager.Others;

internal readonly struct DeviceGuardStatus(uint? usermodeCodeIntegrityPolicyEnforcementStatus, uint? codeIntegrityPolicyEnforcementStatus)
{
	internal readonly uint? UsermodeCodeIntegrityPolicyEnforcementStatus => usermodeCodeIntegrityPolicyEnforcementStatus;
	internal readonly uint? CodeIntegrityPolicyEnforcementStatus => codeIntegrityPolicyEnforcementStatus;
}

internal static class DeviceGuardInfo
{

	// Define the WMI query to get the Win32_DeviceGuard class information
	// private const string query = "SELECT UsermodeCodeIntegrityPolicyEnforcementStatus, CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard";

	// Define the scope (namespace) for the query
	// private const string scope = @"\\.\root\Microsoft\Windows\DeviceGuard";


	/// <summary>
	/// Get the Device Guard status information from the Win32_DeviceGuard WMI class
	/// </summary>
	/// <returns></returns>
	internal static DeviceGuardStatus? GetDeviceGuardStatus()
	{

		/*

		// Create a ManagementScope object for the WMI namespace
		ManagementScope managementScope = new(scope);

		// Create an ObjectQuery to specify the WMI query
		ObjectQuery objectQuery = new(query);

		// Create a ManagementObjectSearcher to execute the query
		using (ManagementObjectSearcher searcher = new(managementScope, objectQuery))
		{
			// Execute the query and retrieve the results
			foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
			{
				// Create an instance of the custom class to hold the result
				DeviceGuardStatus status = new()
				{
					// Retrieve the relevant properties and assign them to the class
					UsermodeCodeIntegrityPolicyEnforcementStatus = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"] as uint?,
					CodeIntegrityPolicyEnforcementStatus = obj["CodeIntegrityPolicyEnforcementStatus"] as uint?
				};

				return status;  // Return the first instance
			}
		}

		*/


		// TODO: Create a Native AOT compatible source generated COM code that won't rely on System.Management or PowerShell

		string UMscript = "(Get-CimInstance -Namespace \\\"root\\Microsoft\\Windows\\DeviceGuard\\\" -Query \\\"SELECT UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard\\\").UsermodeCodeIntegrityPolicyEnforcementStatus";
		string UMoutput = ProcessStarter.RunCommandWithOutput("powershell.exe", $"-NoProfile -Command \"{UMscript}\"");


		string KMscript = "(Get-CimInstance -Namespace \\\"root\\Microsoft\\Windows\\DeviceGuard\\\" -Query \\\"SELECT CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard\\\").CodeIntegrityPolicyEnforcementStatus";
		string KMoutput = ProcessStarter.RunCommandWithOutput("powershell.exe", $"-NoProfile -Command \"{KMscript}\"");


		return new DeviceGuardStatus(
			usermodeCodeIntegrityPolicyEnforcementStatus: uint.Parse(UMoutput),
			codeIntegrityPolicyEnforcementStatus: uint.Parse(KMoutput)
		);
	}
}
