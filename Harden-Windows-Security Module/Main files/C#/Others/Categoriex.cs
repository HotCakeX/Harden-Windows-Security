using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace HardenWindowsSecurity;

public enum ComplianceCategories
{
	MicrosoftDefender, // 55 + Number of Process Mitigations which are dynamically increased
	AttackSurfaceReductionRules, // 19 rules
	BitLockerSettings, // 21 + conditional item for Hibernation check (only available on non-VMs) + Number of Non-OS drives which are dynamically increased
	TLSSecurity, // 21
	LockScreen, // 14
	UserAccountControl, // 6
	DeviceGuard, // 10
	WindowsFirewall, // 20
	OptionalWindowsFeatures, // 15
	WindowsNetworking, // 17
	MiscellaneousConfigurations, // 20
	WindowsUpdateConfigurations, // 15
	EdgeBrowserConfigurations, // 18
	NonAdminCommands // 9
}


// This class is the orchestrator of the hardening categories deciding which one of them is allowed to run
public static class ProtectionCategoriex
{
	// a method to detect Windows edition SKU number
	private static bool IsWindowsHome()
	{
		using ManagementObjectSearcher searcher = new("SELECT OperatingSystemSKU FROM Win32_OperatingSystem");

		foreach (ManagementObject os in searcher.Get().Cast<ManagementObject>())
		{
			// check for SKU of Windows Home and Windows Home Single Language
			int sku = (int)(uint)os["OperatingSystemSKU"];
			if (sku == 101 || sku == 100)
			{
				return true;
			}
		}
		return false;
	}

	// Detect if TPM is present on the system
	private static bool IsTpmPresentAndEnabled()
	{
		try
		{
			// Create a ManagementScope for the TPM namespace
			ManagementScope scope = new(@"\\.\root\CIMv2\Security\MicrosoftTpm");
			scope.Connect();

			// Create an ObjectQuery to query the Win32_Tpm class
			ObjectQuery query = new("SELECT * FROM Win32_Tpm");

			// Create a ManagementObjectSearcher to execute the query
			using ManagementObjectSearcher searcher = new(scope, query);

			// Get the TPM instances
			ManagementObjectCollection queryCollection = searcher.Get();

			if (queryCollection.Count > 0)
			{
				return true;
				//   foreach (ManagementObject tpm in queryCollection)
				//    {
				//     Logger.LogMessage("TPM is present on this system.");
				//     Logger.LogMessage("TPM Version: " + tpm["SpecVersion"]);
				//    }
			}
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException("An error occurred while checking TPM status.", ex);
		}
		return false;
	}


	/// <summary>
	/// Main method of the class to return the final authorized categories for Protection
	/// For PowerShell cmdlets and GUI elements that will light up based on different criteria
	/// </summary>
	/// <returns></returns>
	public static string[] GetValidValues()
	{
		// if running under unelevated context then only return the NonAdminCommands category
		if (!Environment.IsPrivilegedProcess) return ["NonAdminCommands"];

		HashSet<string> categoriex =
		[
			"MicrosoftSecurityBaselines",
			"Microsoft365AppsSecurityBaselines",
			"MicrosoftDefender",
			"AttackSurfaceReductionRules",
			"BitLockerSettings",
			"DeviceGuard",
			"TLSSecurity",
			"LockScreen",
			"UserAccountControl",
			"WindowsFirewall",
			"OptionalWindowsFeatures",
			"WindowsNetworking",
			"MiscellaneousConfigurations",
			"WindowsUpdateConfigurations",
			"EdgeBrowserConfigurations",
			"CertificateCheckingCommands",
			"CountryIPBlocking",
			"DownloadsDefenseMeasures",
			"NonAdminCommands"
		];

		// Remove the categories that are not applicable to Windows Home editions
		if (IsWindowsHome())
		{
			string[] homeEditionCategories =
			[
				"BitLockerSettings",
				"DeviceGuard",
				"DownloadsDefenseMeasures",
				"TLSSecurity",
				"AttackSurfaceReductionRules",
				"MicrosoftSecurityBaselines",
				"Microsoft365AppsSecurityBaselines",
				"CountryIPBlocking"
			];
			foreach (string category in homeEditionCategories)
			{
				_ = categoriex.Remove(category);
			}
		}

		// Remove the BitLockerSettings category if TPM is not present on the systems
		if (!IsTpmPresentAndEnabled())
		{
			_ = categoriex.Remove("BitLockerSettings");
		}

		return [.. categoriex];
	}
}
