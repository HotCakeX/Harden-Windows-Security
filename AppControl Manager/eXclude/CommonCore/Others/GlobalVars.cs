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

using System.IO;

namespace CommonCore.Others;

/// <summary>
/// This class defines constants and other variables used by the entire application
/// </summary>
internal static partial class GlobalVars
{
	// User Mode block rules
	//internal static readonly Uri MSFTRecommendedBlockRulesURL = new("https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol.md");
	internal static readonly Uri MSFTRecommendedBlockRulesURL = new("https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol");

	// Kernel Mode block rules
	internal static readonly Uri MSFTRecommendedDriverBlockRulesURL = new("https://aka.ms/VulnerableDriverBlockList");

	// Storing the path to the Code Integrity Schema XSD file
	internal static readonly string CISchemaPath = Path.Combine(
		Environment.GetEnvironmentVariable("SystemDrive") + @"\",
		"Windows", "schemas", "CodeIntegrity", "cipolicy.xsd");

	// The link to the file that contains the download link for the latest version of the AppControl Manager
	internal static readonly Uri AppUpdateDownloadLinkURL = new("https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/MSIXBundleDownloadURL.txt");

	// The link to the file that contains the version number of the latest available version of the app
	internal static readonly Uri AppVersionLinkURL = new("https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/version.txt");

	// Product ID of the application when installed from the Microsoft Store
#if HARDEN_SYSTEM_SECURITY
	internal const string StoreProductID = "9P7GGFL7DX57";
#endif
#if APP_CONTROL_MANAGER
	internal const string StoreProductID = "9PNG1JDDTGP8";
#endif

	// The filters for the file pickers dialogs to select files based on specific extensions
	internal const string XMLFilePickerFilter = "XML file|*.xml";
	internal const string ZIPFilePickerFilter = "ZIP file|*.zip";
	internal const string XSDFilePickerFilter = "XSD file|*.xsd";
	internal const string XMLAndCIPFilePickerFilter = "XML and CIP files (*.xml;*.cip)|*.xml;*.cip";
	internal const string AnyFilePickerFilter = "Any file (*.*)|*.*";
	internal const string ExecutablesPickerFilter = "Executable file|*.exe";
	internal const string CertificatePickerFilter = "Certificate file|*.cer";
	internal const string EVTXPickerFilter = "EVTX log file|*.evtx";
	internal const string JSONAndPOLPickerFilter = "JSON and POL files (*.json;*.pol)|*.json;*.pol";
	internal const string POLPickerFilter = "Group Policy File|*.pol";
	internal const string JSONPickerFilter = "JSON Files|*.json";
	internal const string SecurityINFPickerFilter = "Security INF Files|*.inf";

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
	internal const string FallBackAppLogoURI = "ms-appx:///Assets/Others/AppWithoutIconPlaceHolder.png";

	// Path to the ComManager program in the App directory
	internal static readonly string ComManagerProcessPath = Path.Combine(CppInteropPath, "ComManager.exe");

	/// <summary>
	/// To store the path to the system drive
	/// </summary>
	internal static readonly string SystemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

#if APP_CONTROL_MANAGER

	static GlobalVars()
	{
		if (!Environment.IsPrivilegedProcess)
			return;

		// Ensure the directory exists
		if (!Directory.Exists(UserConfigDir))
		{
			_ = Directory.CreateDirectory(UserConfigDir);
		}
	}

#endif

}
