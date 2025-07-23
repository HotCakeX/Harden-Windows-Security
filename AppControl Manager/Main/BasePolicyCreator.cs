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
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.XMLOps;

namespace AppControlManager.Main;

internal static partial class BasePolicyCreator
{

	private static MainWindowVM ViewModel { get; } = ViewModelProvider.MainWindowVM;

	/// <summary>
	/// Creates scheduled task that keeps the Microsoft recommended driver block rules up to date on the system
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void SetAutoUpdateDriverBlockRules()
	{
		Logger.Write(GlobalVars.GetStr("CreatingScheduledTaskForFastWeeklyDriverBlockListUpdateMessage"));

		/*

		// Initialize ManagementScope to interact with Task Scheduler's WMI namespace
		ManagementScope scope = new(@"root\Microsoft\Windows\TaskScheduler");
		// Establish connection to the WMI namespace
		scope.Connect();


		#region Action
		// Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
		using ManagementClass actionClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

		// Prepare method parameters for creating the task action
		ManagementBaseObject actionInParams = actionClass.GetMethodParameters("NewActionByExec");
		actionInParams["Execute"] = "PowerShell.exe";
		// The PowerShell command to run, downloading and deploying the drivers block list
		actionInParams["Argument"] = """
-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop}catch{exit 1};Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force;$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1;Move-Item -Path $SiPolicy_EnforcedFile.FullName -Destination ($env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force;citool --refresh -json;Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force;Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force;}"
""";

		// Execute the WMI method to create the action
		ManagementBaseObject actionResult = actionClass.InvokeMethod("NewActionByExec", actionInParams, null);

		// Check if the action was created successfully
		if ((uint)actionResult["ReturnValue"] != 0)
		{
			throw new InvalidOperationException($"Failed to create task action: {((uint)actionResult["ReturnValue"])}");
		}

		// Extract CIM instance for further use in task registration
		ManagementBaseObject actionCimInstance = (ManagementBaseObject)actionResult["cmdletOutput"];

		#endregion


		#region Principal
		// Create a scheduled task principal and assign the SYSTEM account's SID to it so that the task will run under its context
		using ManagementClass principalClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

		// Prepare method parameters to set up the principal (user context)
		ManagementBaseObject principalInParams = principalClass.GetMethodParameters("NewPrincipalByUser");
		principalInParams["UserId"] = "S-1-5-18"; // SYSTEM SID (runs with the highest system privileges)
		principalInParams["LogonType"] = 2; // S4U logon type, allows the task to run without storing credentials
		principalInParams["RunLevel"] = 1; // Highest run level, ensuring the task runs with elevated privileges

		// Execute the WMI method to create the principal
		ManagementBaseObject principalResult = principalClass.InvokeMethod("NewPrincipalByUser", principalInParams, null);

		// Check if the principal was created successfully
		if ((uint)principalResult["ReturnValue"] != 0)
		{
			throw new InvalidOperationException($"Failed to create task principal: {((uint)principalResult["ReturnValue"])}");
		}

		// Extract CIM instance for further use in task registration
		ManagementBaseObject principalCimInstance = (ManagementBaseObject)principalResult["cmdletOutput"];
		#endregion


		#region Trigger
		// Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
		using ManagementClass triggerClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

		// Prepare method parameters for setting the task trigger
		// DateTime and TimeSpan are .NET constructs that are not directly compatible with WMI methods, which require the use of DMTF DateTime and TimeInterval formats.
		// The conversion ensures that time-related parameters (e.g., DateTime.Now.AddHours(1) or TimeSpan.FromDays(7)) are formatted in a way that the WMI provider can interpret them correctly.
		// The ManagementDateTimeConverter class provides methods like ToDmtfDateTime and ToDmtfTimeInterval that perform these necessary conversions.

		ManagementBaseObject triggerInParams = triggerClass.GetMethodParameters("NewTriggerByOnce");
		triggerInParams["Once"] = true; // This switch indicates the task should run once
		triggerInParams["At"] = ManagementDateTimeConverter.ToDmtfDateTime(DateTime.Now.AddHours(1)); // Convert the current time +1 hour to DMTF format
		triggerInParams["RepetitionInterval"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromDays(7)); // Convert 7-day interval to DMTF format

		// Execute the WMI method to create the trigger
		ManagementBaseObject triggerResult = triggerClass.InvokeMethod("NewTriggerByOnce", triggerInParams, null);

		// Check if the trigger was created successfully
		if ((uint)triggerResult["ReturnValue"] != 0)
		{
			throw new InvalidOperationException($"Failed to create task trigger: {((uint)triggerResult["ReturnValue"])}");
		}

		// Extract CIM instance for further use in task registration
		ManagementBaseObject triggerCimInstance = (ManagementBaseObject)triggerResult["cmdletOutput"];
		#endregion


		#region Settings
		// Define advanced settings for the scheduled task
		using ManagementClass settingsClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

		// Prepare method parameters to define advanced settings for the task
		ManagementBaseObject settingsInParams = settingsClass.GetMethodParameters("NewSettings");
		settingsInParams["AllowStartIfOnBatteries"] = true; // Allow the task to start if the system is on battery
		settingsInParams["DontStopIfGoingOnBatteries"] = true; // Ensure the task isn't stopped if the system switches to battery power
		settingsInParams["Compatibility"] = 4;
		settingsInParams["StartWhenAvailable"] = true; // Start the task if it missed a scheduled time but becomes available
		settingsInParams["RunOnlyIfNetworkAvailable"] = true; // Run the task only if a network is available
		settingsInParams["ExecutionTimeLimit"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromMinutes(3)); // Limit task execution time to 3 minutes (converted to DMTF format)
		settingsInParams["RestartCount"] = 4; // Number of allowed task restarts on failure
		settingsInParams["RestartInterval"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromHours(6)); // Wait 6 hours between restarts (converted to DMTF format)

		// Execute the WMI method to set the task's advanced settings
		ManagementBaseObject settingsResult = settingsClass.InvokeMethod("NewSettings", settingsInParams, null);
		if ((uint)settingsResult["ReturnValue"] != 0)
		{
			throw new InvalidOperationException($"Failed to define task settings: {((uint)settingsResult["ReturnValue"])}");
		}

		// Extract CIM instance for further use in task registration
		ManagementBaseObject settingsCimInstance = (ManagementBaseObject)settingsResult["cmdletOutput"];
		#endregion


		#region Register Task
		// Register the scheduled task.
		// If the task's state is disabled or its configuration is invalid, it will be replaced with a new correct task as this step is overwriting.
		using ManagementClass registerClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

		// Prepare method parameters to register the task
		ManagementBaseObject registerInParams = registerClass.GetMethodParameters("RegisterByPrincipal");
		registerInParams["Force"] = true; // Overwrite any existing task with the same name
		registerInParams["Principal"] = principalCimInstance;
		registerInParams["Action"] = new ManagementBaseObject[] { actionCimInstance };
		registerInParams["Trigger"] = new ManagementBaseObject[] { triggerCimInstance };
		registerInParams["Settings"] = settingsCimInstance;
		registerInParams["TaskPath"] = @"\MSFT Driver Block list update";
		registerInParams["TaskName"] = "MSFT Driver Block list update";
		registerInParams["Description"] = "Microsoft Recommended Driver Block List update";

		// Execute the WMI method to register the task
		ManagementBaseObject registerResult = registerClass.InvokeMethod("RegisterByPrincipal", registerInParams, null);

		// Check if the task was registered successfully
		if ((uint)registerResult["ReturnValue"] != 0)
		{
			throw new InvalidOperationException($"Failed to register the task: {((uint)registerResult["ReturnValue"])}");
		}
		#endregion

		Logger.Write("Successfully created the Microsoft Recommended Driver Block Rules auto updater scheduled task.");

		*/

		const string command = """
-NoProfile -WindowStyle Hidden -Command ""try { Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop } catch { exit 1 };
Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force;
$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1;
Move-Item -Path $SiPolicy_EnforcedFile.FullName -Destination ($env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force;
$null = CiTool.exe --refresh -json;
Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force;
Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force;""
""";

		DateTime currentTimePlus6 = DateTime.UtcNow.AddHours(6);

		string formattedTime = currentTimePlus6.ToString("yyyy-MM-ddTHH:mm:ss");

		string args = $"""
--name "MSFT Driver Block list update" --exe "PowerShell.exe" --arg "{command}" --folder "MSFT Driver Block list update" --description "This scheduled task runs every 7 days to keep the Microsoft Recommended Drivers Block List up to date. It uses Windows PowerShell for execution. It was created by the AppControl Manager application when you used the feature in the 'Create Policy' page." --author "AppControl Manager" --logon 2 --runlevel 1 --sid "S-1-5-18" --allowstartifonbatteries --dontstopifgoingonbatteries --startwhenavailable --restartcount 4 --restartinterval PT6H --priority 4 --runonlyifnetworkavailable --trigger "type=onetime;start={formattedTime};repeat_interval=P7D;execution_time_limit=PT1H;stop_at_duration_end=1;" --useunifiedschedulingengine true --executiontimelimit PT4M --waketorun 0 --multipleinstancespolicy 2 --allowhardterminate 1 --allowdemandstart 1
""";

		_ = ProcessStarter.RunCommand(GlobalVars.ScheduledTaskManagerProcessPath, args);
	}


	/// <summary>
	/// Used to supply extra information regarding Microsoft recommended driver block rules
	/// </summary>
	/// <returns></returns>
	internal static DateTime? DriversBlockListInfoGathering()
	{
		try
		{
			// The returned date is based on the local system's time-zone

			// Set variables
			const string owner = "MicrosoftDocs";
			const string repo = "windows-itpro-docs";
			const string path = "windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md";

			Uri apiUrl = new($"https://api.github.com/repos/{owner}/{repo}/commits?path={path}");

			using HttpClient httpClient = new SecHttpClient();
			httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36");

			// Call GitHub API to get commit details
			string response = httpClient.GetStringAsync(apiUrl).GetAwaiter().GetResult();

			// Use JsonDocument to parse the JSON response
			using JsonDocument document = JsonDocument.Parse(response);
			JsonElement root = document.RootElement;

			// Extract the date of the latest commit
			string? dateString = root[0].GetProperty("commit")
									   .GetProperty("author")
									   .GetProperty("date")
									   .GetString();

			DateTime lastUpdated = DateTime.MinValue;

			if (dateString is not null)
			{
				lastUpdated = DateTime.Parse(dateString, CultureInfo.InvariantCulture);

				Logger.Write(string.Format(
					GlobalVars.GetStr("DriversBlockListLastUpdatedMessage"),
					lastUpdated));
			}

			return lastUpdated;
		}
		catch (Exception ex)
		{
			Logger.Write(GlobalVars.GetStr("ErrorRetrievingAdditionalDriverBlockRulesInfoMessage"));

			Logger.Write(ErrorWriter.FormatException(ex));

			// Return null in case of an error
			return null;
		}
	}


	/// <summary>
	/// A method to deploy the Vulnerable Driver Block List from the Microsoft servers and deploy it to the system
	/// </summary>
	/// <param name="StagingArea">The directory to use for temporary files</param>
	/// <exception cref="Exception"></exception>
	internal static (string?, string) DeployDriversBlockRules(string StagingArea)
	{
		// The location where the downloaded zip file will be saved
		string DownloadSaveLocation = Path.Combine(StagingArea, "VulnerableDriverBlockList.zip");

		// The location where the zip file will be extracted
		string ZipExtractionDir = Path.Combine(StagingArea, "VulnerableDriverBlockList");

		// Initialize the final destination of the SiPolicy file
		string SiPolicyFinalDestination = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "CodeIntegrity", "SiPolicy.p7b");

		// Download the zip file
		using (HttpClient client = new())
		{
			// Download the file synchronously
			byte[] fileBytes = client.GetByteArrayAsync(GlobalVars.MSFTRecommendedDriverBlockRulesURL)
									 .GetAwaiter().GetResult();
			File.WriteAllBytes(DownloadSaveLocation, fileBytes);
		}

		// Extract the contents of the zip file, overwriting any existing files
		ZipFile.ExtractToDirectory(DownloadSaveLocation, ZipExtractionDir, true);

		// Get the path of the SiPolicy file
		string[] SiPolicyPaths = Directory.GetFiles(
			ZipExtractionDir,
			"SiPolicy_Enforced.p7b",
			SearchOption.AllDirectories);

		// Make sure to get only one file if there is more than one (which is unexpected)
		string SiPolicyPath = SiPolicyPaths[0];

		// Get the path of the XML file - just to extract the version
		string[] XMLFilePaths = Directory.GetFiles(
			ZipExtractionDir,
			"SiPolicy_Enforced.xml",
			SearchOption.AllDirectories);

		// Make sure to get only one file if there is more than one (which is unexpected)
		string XMLFilePath = XMLFilePaths[0];

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(XMLFilePath, null);

		string policyVersion = policyObj.VersionEx;

		// If the SiPolicy file already exists, delete it
		if (File.Exists(SiPolicyFinalDestination))
		{
			File.Delete(SiPolicyFinalDestination);
		}

		// Move the SiPolicy file to the final destination, renaming it in the process
		File.Move(SiPolicyPath, SiPolicyFinalDestination);

		Logger.Write(GlobalVars.GetStr("DeployDriversBlockRulesRefreshPoliciesMessage"));
		CiToolHelper.RefreshPolicy();

		Logger.Write(GlobalVars.GetStr("DeployDriversBlockRulesDeployedMessage"));

		return (null, policyVersion);
	}


	/// <summary>
	/// Downloads the latest Microsoft Recommended Block rules from Microsoft's GitHub repository
	/// And creates a valid Code Integrity XML policy file from it.
	/// </summary>
	/// <param name="StagingArea">The directory where the XML file will be saved to.</param>
	/// <returns>the path to the Microsoft recommended driver block rules base policy path and the policy version</returns>
	internal static (string, string) GetDriversBlockRules(string StagingArea)
	{
		const string name = "Microsoft Recommended Driver Block Rules";

		// The location where the downloaded zip file will be saved
		string DownloadSaveLocation = Path.Combine(StagingArea, "VulnerableDriverBlockList.zip");

		// The location where the zip file will be extracted
		string ZipExtractionDir = Path.Combine(StagingArea, "VulnerableDriverBlockList");

		// Download the zip file
		using (HttpClient client = new())
		{
			// Download the file synchronously
			byte[] fileBytes = client.GetByteArrayAsync(GlobalVars.MSFTRecommendedDriverBlockRulesURL).GetAwaiter().GetResult();
			File.WriteAllBytes(DownloadSaveLocation, fileBytes);
		}

		// Extract the contents of the zip file, overwriting any existing files
		ZipFile.ExtractToDirectory(DownloadSaveLocation, ZipExtractionDir, true);

		// Get the path of the XML file
		string[] SiPolicyPaths = Directory.GetFiles(ZipExtractionDir, "SiPolicy_Enforced.xml", SearchOption.AllDirectories);

		// Make sure to get only one file if there is more than one (which is unexpected)
		string SiPolicyPath = SiPolicyPaths[0];

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(SiPolicyPath, null);

		// Set the policy name
		PolicySettingsManager.SetPolicyName(policyObj, name);

		string policyVersion = policyObj.VersionEx;

		// Generate the path for the XML file
		string xmlPath = Path.Combine(StagingArea, $"{name}.xml");

		// Save the XML content to a file
		SiPolicy.Management.SavePolicyToFile(policyObj, xmlPath);

		CiRuleOptions.Set(filePath: xmlPath, rulesToRemove: [SiPolicy.OptionType.EnabledAuditMode]);

		// The final path where the XML policy file will be located
		string savePathLocation = Path.Combine(GlobalVars.UserConfigDir, $"{name}.xml");

		// Copy the result to the User Config directory at the end
		File.Copy(xmlPath, savePathLocation, true);

		Logger.Write(string.Format(
			  GlobalVars.GetStr("PolicyFileCreatedSavedMessage"),
			  savePathLocation));

		return (savePathLocation, policyVersion);
	}


	/// <summary>
	/// Creates and deploys an AllowMicrosoft policy based on various configurations and parameters.
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where temporary policy files are stored during processing.</param>
	/// <param name="IsAudit">Indicates whether the policy should operate in audit mode, affecting logging behavior.</param>
	/// <param name="LogSize">Sets the size of the log for audit events, defaulting to zero if not specified.</param>
	/// <param name="deploy">Determines if the policy should be deployed after creation, enabling further actions.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled within the policy.</param>
	/// <param name="TestMode">Indicates if the policy should be created in test mode, affecting its execution.</param>
	/// <param name="deployAppControlSupplementalPolicy">Indicates if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific policy ID if provided, overriding the generated one.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Specifies whether to deploy recommended block rules if no policy ID is provided.</param>
	/// <returns>Returns the path to the created policy</returns>
	internal static string BuildAllowMSFT(string StagingArea, bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules)
	{

		string policyName;

		if (IsAudit)
		{
			EventLogUtility.SetLogSize(LogSize ?? 0);

			policyName = "AllowMicrosoftAudit";
		}
		else
		{
			policyName = "AllowMicrosoft";
		}

		// Paths only used during staging area processing
		string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");
		string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

		// Final Policy Path
		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(StagingArea, deploy);

		File.Copy(GlobalVars.AllowMicrosoftTemplatePolicyPath, tempPolicyPath, true);

		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Get the policy ID of the policy being created
		string policyID = SetCiPolicyInfo.Set(
			tempPolicyPath,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null,
			null);

		if (PolicyIDToUse is not null)
		{
			policyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(StagingArea, policyID);
		}

		// Finalize CI policy metadata
		SetCiPolicyInfo.Set(
			tempPolicyPath,
			new Version("1.0.0.0"),
			PolicyIDToUse);

		// Apply rule options
		CiRuleOptions.Set(
			tempPolicyPath,
			template: CiRuleOptions.PolicyTemplate.Base,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);

		if (deploy)
		{
			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			SiPolicy.Management.ConvertXMLToBinary(
				tempPolicyPath,
				null,
				tempPolicyCIPPath);

			CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
		}

		File.Copy(tempPolicyPath, finalPolicyPath, true);

		// Assign the created policy path to the Sidebar if condition is met
		ViewModel.AssignToSidebar(finalPolicyPath);

		return finalPolicyPath;
	}


	/// <summary>
	/// Creates and configures a DefaultWindows policy based on various parameters, handling staging and deployment
	/// options.
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where temporary policy files are stored during processing.</param>
	/// <param name="IsAudit">Indicates whether the policy should operate in audit mode, affecting logging behavior.</param>
	/// <param name="LogSize">Sets the size limit for the event log if audit mode is enabled.</param>
	/// <param name="deploy">Determines whether the policy should be deployed after creation.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled in the policy.</param>
	/// <param name="TestMode">Indicates if the policy should be created in test mode, affecting its enforcement.</param>
	/// <param name="deployAppControlSupplementalPolicy">Specifies if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific policy ID instead of generating a new one.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Indicates whether to retrieve and deploy Microsoft recommended block rules.</param>
	/// <returns>Returns the path to the created Default Windows base policy</returns>
	internal static string BuildDefaultWindows(string StagingArea, bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules)
	{

		string policyName;

		if (IsAudit)
		{
			EventLogUtility.SetLogSize(LogSize ?? 0);
			policyName = "DefaultWindowsAudit";
		}
		else
		{
			policyName = "DefaultWindows";
		}

		// Paths only used during staging area processing
		string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");
		string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

		// Final Policy Path
		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(StagingArea, deploy);

		File.Copy(GlobalVars.DefaultWindowsTemplatePolicyPath, tempPolicyPath, true);

		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Get the policy ID of the policy being created
		string policyID = SetCiPolicyInfo.Set(
			tempPolicyPath,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null,
			null);

		if (PolicyIDToUse is not null)
		{
			policyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(StagingArea, policyID);
		}

		// Finalize CI policy metadata
		SetCiPolicyInfo.Set(
			tempPolicyPath,
			new Version("1.0.0.0"),
			PolicyIDToUse);

		// Apply rule options
		CiRuleOptions.Set(
			tempPolicyPath,
			template: CiRuleOptions.PolicyTemplate.Base,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);

		if (deploy)
		{
			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			SiPolicy.Management.ConvertXMLToBinary(
				tempPolicyPath,
				null,
				tempPolicyCIPPath);

			CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
		}

		File.Copy(tempPolicyPath, finalPolicyPath, true);

		// Assign the created policy path to the Sidebar if condition is met
		ViewModel.AssignToSidebar(finalPolicyPath);

		return finalPolicyPath;
	}


	/// <summary>
	/// Gets the latest Microsoft Recommended block rules for User Mode files, removes the audit mode policy rule option and sets HVCI to strict
	/// It generates a XML file compliant with CI Policies Schema.
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where temporary policy files are stored during processing.</param>
	/// <param name="deploy">Indicates whether the policy should be deployed after processing.</param>
	/// <exception cref="InvalidOperationException">Thrown when no XML content is found in the downloaded markdown from the Microsoft GitHub source.</exception>
	/// <returns>path to the created policy.</returns>
	internal static string GetBlockRules(string StagingArea, bool deploy)
	{

		const string policyName = "Microsoft Windows Recommended User Mode BlockList";

		Logger.Write(string.Format(
			GlobalVars.GetStr("GettingLatestPolicyFromOfficialRepoMessage"),
			policyName));

		// Download the markdown page from GitHub containing the latest Microsoft recommended block rules (User Mode)
		string msftUserModeBlockRulesAsString;
		using (HttpClient client = new SecHttpClient())
		{
			msftUserModeBlockRulesAsString = client
				.GetStringAsync(GlobalVars.MSFTRecommendedBlockRulesURL)
				.GetAwaiter()
				.GetResult();
		}

		// Extracted the XML content from the markdown string will saved in this variable
		string xmlContent;

		// Extract the XML content with Regex
		Match match = XMLCaptureRegex().Match(msftUserModeBlockRulesAsString);

		if (match.Success)
		{
			// Capture the XML content
			xmlContent = match.Groups[1].Value;
		}
		else
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("NoXmlContentFoundForUserModeBlockRulesErrorMessage"));
		}

		// Load the XML content into an XmlDocument
		XmlDocument userModeBlockRulesXML = new();
		userModeBlockRulesXML.LoadXml(xmlContent);

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(
			null,
			userModeBlockRulesXML);

		// Paths only used during staging area processing
		string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");
		string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

		// Save the XML content to a file
		SiPolicy.Management.SavePolicyToFile(policyObj, tempPolicyPath);

		CiRuleOptions.Set(
			filePath: tempPolicyPath,
			rulesToAdd: [SiPolicy.OptionType.EnabledUpdatePolicyNoReboot, SiPolicy.OptionType.DisabledScriptEnforcement],
			rulesToRemove: [SiPolicy.OptionType.EnabledAuditMode, SiPolicy.OptionType.EnabledAdvancedBootOptionsMenu]);

		Logger.Write(GlobalVars.GetStr("AssigningPolicyNameAndResettingPolicyIDMessage"));

		// Get the policyID of the policy being created
		_ = SetCiPolicyInfo.Set(tempPolicyPath, true, policyName, null, null);

		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

		if (deploy)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("CheckingIfPolicyIsAlreadyDeployedMessage"),
				policyName));

			// Getting the list of the deployed base policies whose names match the policyName
			List<CiPolicyInfo> CurrentlyDeployedBlockRules =
				CiToolHelper.GetPolicies(false, true, false)
				.Where(policy => string.Equals(
					policy.FriendlyName,
					policyName,
					StringComparison.OrdinalIgnoreCase))
				.ToList();

			// If any policy was found
			if (CurrentlyDeployedBlockRules.Count > 0)
			{
				// Get the ID of the policy
				string CurrentlyDeployedBlockRulesGUID = CurrentlyDeployedBlockRules.First().PolicyID!;

				Logger.Write(string.Format(
					GlobalVars.GetStr("PolicyAlreadyDeployedUpdatingUsingSameGuidMessage"),
					policyName,
					CurrentlyDeployedBlockRulesGUID));

				// Swap the policyID in the current policy XML file with the one from the deployed policy
				XMLOps.PolicyEditor.EditGuids(CurrentlyDeployedBlockRulesGUID, tempPolicyPath);
			}
			else
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("PolicyNotDeployedDeployingNowMessage"),
					policyName));
			}

			// Convert it to CIP
			SiPolicy.Management.ConvertXMLToBinary(tempPolicyPath, null, tempPolicyCIPPath);

			// Deploy the CIP file
			CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
		}

		File.Copy(tempPolicyPath, finalPolicyPath, true);

		return finalPolicyPath;
	}


	/// <summary>
	/// Creates SignedAndReputable App Control policy which is based on AllowMicrosoft template policy.
	/// It uses ISG to authorize files with good reputation.
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where temporary policy files are stored during processing.</param>
	/// <param name="IsAudit">Indicates whether the operation should be performed in audit mode.</param>
	/// <param name="LogSize">Sets the size of the event log for recording actions taken during the process.</param>
	/// <param name="deploy">Determines if the policy should be deployed after creation.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled in the policy.</param>
	/// <param name="TestMode">Indicates if the operation should run in test mode without making permanent changes.</param>
	/// <param name="deployAppControlSupplementalPolicy">Indicates if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific policy ID if provided, overriding the generated one.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Specifies whether to retrieve and deploy Microsoft recommended block rules.</param>
	/// <returns>Returns the signed and reputable base policy file path</returns>
	internal static string BuildSignedAndReputable(string StagingArea, bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules)
	{

		string policyName;

		if (IsAudit)
		{
			EventLogUtility.SetLogSize(LogSize ?? 0);

			policyName = "SignedAndReputableAudit";
		}
		else
		{
			policyName = "SignedAndReputable";
		}

		// Paths only used during staging area processing
		string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");
		string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

		// Final policy XML path
		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(StagingArea, deploy);

		File.Copy(GlobalVars.AllowMicrosoftTemplatePolicyPath, tempPolicyPath, true);

		CiRuleOptions.Set(
			tempPolicyPath,
			template: CiRuleOptions.PolicyTemplate.BaseISG,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);


		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Get the policyID of the policy being created
		string policyID = SetCiPolicyInfo.Set(
			tempPolicyPath,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null,
			null);

		if (PolicyIDToUse is not null)
		{
			policyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(StagingArea, policyID);
		}

		SetCiPolicyInfo.Set(tempPolicyPath, new Version("1.0.0.0"), PolicyIDToUse);

		if (deploy)
		{
			ConfigureISGServices.Configure();

			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			SiPolicy.Management.ConvertXMLToBinary(tempPolicyPath, null, tempPolicyCIPPath);

			CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
		}

		File.Copy(tempPolicyPath, finalPolicyPath, true);

		// Assign the created policy path to the Sidebar if condition is met
		ViewModel.AssignToSidebar(finalPolicyPath);

		return finalPolicyPath;
	}


	/// <summary>
	/// Creates and deploys the Strict Kernel-mode base policy
	/// Since this is only Kernel-mode, we don't need to deploy the special AppControl Manager supplemental policy
	/// </summary>
	/// <param name="StagingArea">Specifies the directory where the policy file will be created and stored.</param>
	/// <param name="IsAudit">Indicates whether to add audit mode rules to the policy.</param>
	/// <param name="NoFlightRoots">Determines the filename variant used for the policy based on flight root settings.</param>
	/// <param name="deploy">Indicates whether the policy should be deployed after creation.</param>
	/// <param name="PolicyIDToUse">Specifies an optional policy ID to associate with the created policy.</param>
	/// <returns>the path to the Strict Kernel-mode base policy path</returns>
	internal static string BuildStrictKernelMode(string StagingArea, bool IsAudit, bool NoFlightRoots, bool deploy, string? PolicyIDToUse = null)
	{

		string fileName = NoFlightRoots ? "StrictKernelMode_NoFlightRoots" : "StrictKernelMode";

		// Path of the policy file in the staging area
		string policyPath = Path.Combine(StagingArea, $"{fileName}.xml");

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		// path of the policy in user configurations directory
		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{fileName}.xml");

		// Copy the policy from app's directory to the staging area
		File.Copy(policyPathInResourcesDir, policyPath, true);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			CiRuleOptions.Set(filePath: policyPath, rulesToAdd: [SiPolicy.OptionType.EnabledAuditMode]);
		}

		string policyID;

		if (PolicyIDToUse is not null)
		{
			SetCiPolicyInfo.Set(policyPath, new Version("1.0.0.0"), PolicyIDToUse);
			policyID = PolicyIDToUse;
		}
		else
		{
			// Reset the policy ID
			policyID = SetCiPolicyInfo.Set(policyPath, true, null, null, null);
		}

		// Copy the policy to the user configurations directory
		File.Copy(policyPath, finalPolicyPath, true);

		// If it is to be deployed
		if (deploy)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("DeployingStrictKernelModePolicyMessage"),
				policyID));

			string cipPath = Path.Combine(StagingArea, $"{fileName}.cip");

			// Convert the XML to CiP
			SiPolicy.Management.ConvertXMLToBinary(policyPath, null, cipPath);

			// Deploy the CiP file
			CiToolHelper.UpdatePolicy(cipPath);
		}

		return finalPolicyPath;
	}

	/// <summary>
	/// Creates the base policy responsible for blocking a large number of RMMs, Remote Monitoring and Management software.
	/// </summary>
	/// <param name="StagingArea"></param>
	/// <param name="IsAudit"></param>
	/// <param name="deploy"></param>
	/// <returns></returns>
	internal static string BuildRMMBlocking(string StagingArea, bool IsAudit, bool deploy)
	{

		const string fileName = "Blocking RMMs - Remote Monitor and Management";

		// Path of the policy file in the staging area
		string policyPath = Path.Combine(StagingArea, $"{fileName}.xml");

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		// path of the policy in user configurations directory
		string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{fileName}.xml");

		// Copy the policy from app's directory to the staging area
		File.Copy(policyPathInResourcesDir, policyPath, true);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			CiRuleOptions.Set(filePath: policyPath, rulesToAdd: [SiPolicy.OptionType.EnabledAuditMode]);
		}

		// Copy the policy to the user configurations directory
		File.Copy(policyPath, finalPolicyPath, true);

		// If it is to be deployed
		if (deploy)
		{
			string cipPath = Path.Combine(StagingArea, $"{fileName}.cip");

			// Convert the XML to CiP
			SiPolicy.Management.ConvertXMLToBinary(policyPath, null, cipPath);

			// Deploy the CiP file
			CiToolHelper.UpdatePolicy(cipPath);
		}

		return finalPolicyPath;
	}

	/// <summary>
	/// Regex pattern to capture XML content between ```xml and ```
	/// </summary>
	/// <returns></returns>
	[GeneratedRegex(@"```xml\s*(.*?)\s*```", RegexOptions.Compiled | RegexOptions.Singleline)]
	private static partial Regex XMLCaptureRegex();

}
