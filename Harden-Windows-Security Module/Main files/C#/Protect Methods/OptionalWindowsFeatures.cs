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
using System.Reflection;

namespace HardenWindowsSecurity;

public static class OptionalWindowsFeatures
{

	/// <summary>
	/// A method that removes the capability if it is present
	/// </summary>
	/// <param name="CapabilityIdentity">the capability's identity, the one that will be used to query its state and to remove it</param>
	/// <param name="CapabilityName">The name of the capability, used to display in the log messages</param>
	internal static void RemoveCapability(string CapabilityIdentity, string CapabilityName)
	{
		// The queried state of the capability
		string CapabilityState = WindowsFeatureChecker.GetCapabilityState(CapabilityIdentity);

		if (string.Equals(CapabilityState, "Not Present", StringComparison.OrdinalIgnoreCase))
		{
			Logger.LogMessage($"The {CapabilityName} is already removed.", LogTypeIntel.Information);
		}
		else if (string.Equals(CapabilityState, "Installed", StringComparison.OrdinalIgnoreCase))
		{
			Logger.LogMessage($"Removing {CapabilityName}", LogTypeIntel.Information);

			// For capabilities, using DISM would do the job but would hang and not exit
			// Running DISM in a different thread wouldn't fix it. DISM has this problem only for capabilities, but for using features DISM works fine.

			// PowerShell script to run to remove the Windows Capability
			string PSScript = $@"
Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
$null = Get-WindowsCapability -Online |
Where-Object -FilterScript {{ $_.Name -like '*{CapabilityIdentity}*' }} |
Remove-WindowsCapability -Online
";

			// Run the PowerShell script
			_ = PowerShellExecutor.ExecuteScript(PSScript);

		}
		else
		{
			Logger.LogMessage($"The {CapabilityName} is in {CapabilityState} state. Skipping.", LogTypeIntel.Information);
		}
	}

	/// <summary>
	/// A Private method that configures the Windows Optional Feature, enables/disables them by checking for their state first
	/// </summary>
	/// <param name="Action">true means the feature should be enabled, false means the feature should be disabled</param>
	/// <param name="FeatureNameToActOn">The exact name of the feature to use when querying/enabling/disabling it, this is what DISM.exe requires and understands</param>
	/// <param name="FriendlyName">the name to display in the displayed messages</param>
	/// <param name="FeatureNameToCheckWith">
	/// The name of the feature to use when checking its state
	/// Since the method uses the values in WindowsFeatureChecker.FeatureStatus class
	/// and they are stored under different names, we need this parameter to create the correct connections
	/// </param>
	internal static void ConfigureWindowsOptionalFeature(bool Action, string FeatureNameToActOn, string FriendlyName, string FeatureNameToCheckWith, WindowsFeatureChecker.FeatureStatus featureResults)
	{
		// If the action is to enable a feature, then check if it's disabled and vise versa
		string ValueToCheckFor = Action ? "Disabled" : "Enabled";
		// Used when performing the action
		string ValueToCheckAgainst = Action ? "Enabled" : "Disabled";
		// Used in the log messages
		string TextToUseForMessages = Action ? "Enabling" : "Disabling";

		// Use reflection to get the property value
		PropertyInfo? propertyInfo = featureResults?.GetType().GetProperty(FeatureNameToCheckWith);

		// To store the value of the property of the featureResults
		string? propertyValue = string.Empty;

		if (propertyInfo is not null)
		{
			propertyValue = propertyInfo.GetValue(featureResults)?.ToString();
		}

		if (string.IsNullOrWhiteSpace(propertyValue))
		{
			Logger.LogMessage($"couldn't get the state of {FeatureNameToCheckWith}", LogTypeIntel.Information);
		}

		if (string.Equals(propertyValue, ValueToCheckAgainst, StringComparison.OrdinalIgnoreCase))
		{
			Logger.LogMessage($"{FriendlyName} is already {ValueToCheckAgainst}", LogTypeIntel.Information);
		}
		else if (string.Equals(propertyValue, ValueToCheckFor, StringComparison.OrdinalIgnoreCase))
		{
			Logger.LogMessage($"{TextToUseForMessages} {FriendlyName}", LogTypeIntel.Information);
			WindowsFeatureChecker.SetWindowsFeature(FeatureNameToActOn, Action);
		}
		else
		{
			Logger.LogMessage($"The {FriendlyName} is in {propertyValue} state. Skipping.", LogTypeIntel.Information);
		}
	}

	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🏅 Optional Features");

		Logger.LogMessage("Running the Optional Windows Features category", LogTypeIntel.Information);

		// Get the results of all optional features once and store them in the static variable to be reused later
		WindowsFeatureChecker.FeatureStatus FeaturesCheckResults = WindowsFeatureChecker.CheckWindowsFeatures();

		ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2", "PowerShell v2", "PowerShellv2", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2Root", "PowerShell v2 root", "PowerShellv2Engine", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(false, "WorkFolders-Client", "Work Folders", "WorkFoldersClient", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(false, "Printing-Foundation-InternetPrinting-Client", "Internet Printing Client", "InternetPrintingClient", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(false, "Windows-Defender-ApplicationGuard", "Deprecated Microsoft Defender Application Guard (MDAG)", "MDAG", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(true, "Containers-DisposableClientVM", "Windows Sandbox", "WindowsSandbox", FeaturesCheckResults);
		ConfigureWindowsOptionalFeature(true, "Microsoft-Hyper-V", "Hyper-V", "HyperV", FeaturesCheckResults);

		RemoveCapability("Media.WindowsMediaPlayer", "The old Windows Media Player");
		RemoveCapability("WMIC", "Deprecated WMIC");
		RemoveCapability("Microsoft.Windows.Notepad.System", "Old classic Notepad");
		RemoveCapability("Microsoft.Windows.WordPad", "Deprecated WordPad");
		RemoveCapability("Microsoft.Windows.PowerShell.ISE", "PowerShell ISE");
		RemoveCapability("App.StepsRecorder", "Deprecated Steps Recorder");
		RemoveCapability("VBSCRIPT", "Deprecated VBScript");
		RemoveCapability("Browser.InternetExplorer", "Internet Explorer Mode for Edge");
	}
}
