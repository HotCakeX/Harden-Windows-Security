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
using System.IO;
using Microsoft.Windows.ApplicationModel.Resources;

namespace AppControlManager.Others;

/// <summary>
/// This class defines constants and other variables used by the entire application
/// </summary>
internal static class GlobalVars
{
	// Instantiate the ResourceLoader object to access the strings in the Resource.resw file
	internal static ResourceLoader Rizz = new();

	/// <summary>
	/// This method is responsible for retrieving localized strings from the resource files based on a key.
	/// </summary>
	/// <param name="key"></param>
	/// <returns></returns>
	internal static string GetStr(string key)
	{
		try
		{
			return Rizz.GetString(key);
		}
		catch (Exception ex)
		{
			Logger.Write($"Error retrieving localized string for key: {key}: {ex.Message}");
			return key;
		}
	}

	// User Mode block rules
	internal static readonly Uri MSFTRecommendedBlockRulesURL = new("https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol.md");

	// Kernel Mode block rules
	internal static readonly Uri MSFTRecommendedDriverBlockRulesURL = new("https://aka.ms/VulnerableDriverBlockList");

	// Storing the path to the Code Integrity Schema XSD file
	internal static readonly string CISchemaPath = Path.Combine(
		Environment.GetEnvironmentVariable("SystemDrive") + @"\",
		"Windows", "schemas", "CodeIntegrity", "cipolicy.xsd");

	// Storing the path to the AppControl Manager folder in the Program Files
	internal static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AppControl Manager");

	// Storing the path to User Config JSON file in the AppControl Manager folder in the Program Files
	internal static readonly string UserConfigJson = Path.Combine(UserConfigDir, "UserConfigurations", "UserConfigurations.json");

	// Storing the path to the StagingArea folder in the AppControl Manager folder in the Program Files
	// Each instance of the App (in case there are more than one at a time) has a unique staging area
	internal static readonly string StagingArea = Path.Combine(UserConfigDir, $"StagingArea-{DateTime.UtcNow:yyyyMMddHHmmssfffffff}");

	// The link to the file that contains the download link for the latest version of the AppControl Manager
	internal static readonly Uri AppUpdateDownloadLinkURL = new("https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/MSIXBundleDownloadURL.txt");

	// The link to the file that contains the version number of the latest available version of the AppControl Manager
	internal static readonly Uri AppVersionLinkURL = new("https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/version.txt");

	// Handle of the main Window - acquired in the MainWindow.xaml.cs
	internal static nint hWnd;

	// Product ID of the application when installed from the Microsoft Store
	internal const string StoreProductID = "9PNG1JDDTGP8";

	// The filters for the file pickers dialogs to select files based on specific extensions
	internal const string XMLFilePickerFilter = "XML file|*.xml";
	internal const string XSDFilePickerFilter = "XSD file|*.xsd";
	internal const string XMLAndCIPFilePickerFilter = "XML and CIP files (*.xml;*.cip)|*.xml;*.cip";
	internal const string AnyFilePickerFilter = "Any file (*.*)|*.*";
	internal const string ExecutablesPickerFilter = "Executable file|*.exe";
	internal const string CertificatePickerFilter = "Certificate file|*.cer";
	internal const string EVTXPickerFilter = "EVTX log file|*.evtx";

	// Name of the special automatic supplemental policy
	internal const string AppControlManagerSpecialPolicyName = "AppControlManagerSupplementalPolicy";

	// Path to the AppControlManagerSpecialPolicyName.xml file
	internal static readonly string AppControlManagerSpecialPolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", $"{AppControlManagerSpecialPolicyName}.xml");

	// Path to the ISGBasedSupplementalPolicy.xml file
	internal static readonly string ISGOnlySupplementalPolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", "ISGBasedSupplementalPolicy.xml");

	// Path to the Allow All template policy file
	internal static readonly string AllowAllTemplatePolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", "Allow All Policy.xml");

	// Path to the Allow Microsoft template policy file
	internal static readonly string AllowMicrosoftTemplatePolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", "Allow Microsoft Template.xml");

	// Path to the Default Windows template policy file
	internal static readonly string DefaultWindowsTemplatePolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", "Default Windows Template.xml");

	// Path to the empty policy file in app resources
	internal static readonly string EmptyPolicyPath = Path.Combine(AppContext.BaseDirectory, "Resources", "EmptyPolicy.xml");

	// Path to the RustInterop directory
	private static readonly string RustInteropPath = Path.Combine(AppContext.BaseDirectory, "RustInterop");

	// Path to the CppInteropPath directory
	private static readonly string CppInteropPath = Path.Combine(AppContext.BaseDirectory, "CppInterop");

	// Get the current OS version
	private static readonly Version CurrentOSVersion = Environment.OSVersion.Version;

	// Version for the build 24H2
	private static readonly Version VersionFor24H2 = new(10, 0, 26100, 0);

	// Determine whether the current OS is older than 24H2
	internal static bool IsOlderThan24H2 => CurrentOSVersion < VersionFor24H2;

	// The namespace of the App Control policies
	internal const string SiPolicyNamespace = "urn:schemas-microsoft-com:sipolicy";

	// When the the list of installed packaged apps is retrieved, this URI is used whenever an installed app doesn't have a valid URI logo path
	internal const string FallBackAppLogoURI = "ms-appx:///Assets/StoreLogo.backup.png";

	// Path to the DeviceGuardWMIRetriever program in the App directory
	internal static readonly string DeviceGuardWMIRetrieverProcessPath = Path.Combine(RustInteropPath, "DeviceGuardWMIRetriever.exe");

	// Path to the ManageDefender program in the App directory
	internal static readonly string ManageDefenderProcessPath = Path.Combine(CppInteropPath, "ManageDefender.exe");

	// Path to the ScheduledTaskManager program in the App directory
	internal static readonly string ScheduledTaskManagerProcessPath = Path.Combine(CppInteropPath, "ScheduledTaskManager.exe");


	static GlobalVars()
	{
		if (!App.IsElevated)
			return;

		// Ensure the directory exists
		if (!Directory.Exists(UserConfigDir))
		{
			_ = Directory.CreateDirectory(UserConfigDir);
		}
	}
}
