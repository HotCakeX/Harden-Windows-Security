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

using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;

namespace AppControlManager.Main;

internal static partial class BasePolicyCreator
{

	/// <summary>
	/// Creates scheduled task that keeps the Microsoft recommended driver block rules up to date on the system
	/// </summary>
	internal static void SetAutoUpdateDriverBlockRules()
	{
		Logger.Write(GlobalVars.GetStr("CreatingScheduledTaskForFastWeeklyDriverBlockListUpdateMessage"));

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
scheduledtasks --name "MSFT Driver Block list update" --exe "PowerShell.exe" --arg "{command}" --folder "MSFT Driver Block list update" --description "This scheduled task runs every 7 days to keep the Microsoft Recommended Drivers Block List up to date. It uses Windows PowerShell for execution. It was created by the AppControl Manager application when you used the feature in the 'Create Policy' page." --author "AppControl Manager" --logon 2 --runlevel 1 --sid "S-1-5-18" --allowstartifonbatteries --dontstopifgoingonbatteries --startwhenavailable --restartcount 4 --restartinterval PT6H --priority 4 --runonlyifnetworkavailable --trigger "type=onetime;start={formattedTime};repeat_interval=P7D;execution_time_limit=PT1H;stop_at_duration_end=1;" --useunifiedschedulingengine true --executiontimelimit PT4M --waketorun 0 --multipleinstancespolicy 2 --allowhardterminate 1 --allowdemandstart 1
""";

		_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, args);
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

			const string owner = "MicrosoftDocs";
			const string repo = "windows-itpro-docs";
			const string path = "windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md";

			Uri apiUrl = new($"https://api.github.com/repos/{owner}/{repo}/commits?path={path}");

			using HttpRequestMessage request = new(HttpMethod.Get, apiUrl);
			request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36");

			using HttpResponseMessage httpResponse = SecHttpClient.Instance.Send(request);
			string response = httpResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();

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

			Logger.Write(ex);

			// Return null in case of an error
			return null;
		}
	}

	/// <summary>
	/// A method to retrieve the Vulnerable Driver Block List from the Microsoft servers and deploy it to the system.
	/// </summary>
	/// <returns>The policy that was downloaded and created.</returns>
	internal static PolicyFileRepresent DeployDriversBlockRules()
	{
		// Initialize the final destination of the SiPolicy file
		string SiPolicyFinalDestination = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "CodeIntegrity", "SiPolicy.p7b");

		// Download the zip file
		byte[] fileBytes = SecHttpClient.Instance.GetByteArrayAsync(GlobalVars.MSFTRecommendedDriverBlockRulesURL)
								 .GetAwaiter().GetResult();

		// Process the zip file in memory
		using MemoryStream zipStream = new(fileBytes);
		using ZipArchive zipArchive = new(zipStream, ZipArchiveMode.Read);

		// Locate the SiPolicy_Enforced.p7b file within the zip archive
		ZipArchiveEntry? siPolicyEntry = zipArchive.Entries.FirstOrDefault(entry => entry.Name.Equals("SiPolicy_Enforced.p7b", StringComparison.OrdinalIgnoreCase)) ?? throw new FileNotFoundException("SiPolicy_Enforced.p7b was not found in the downloaded zip file.");

		// Locate the SiPolicy_Enforced.xml file within the zip archive
		ZipArchiveEntry? xmlEntry = zipArchive.Entries.FirstOrDefault(entry => entry.Name.Equals("SiPolicy_Enforced.xml", StringComparison.OrdinalIgnoreCase)) ?? throw new FileNotFoundException("SiPolicy_Enforced.xml was not found in the downloaded zip file.");

		// Load the content of the XML file into an XmlDocument
		XmlDocument xmlDoc = new();
		using Stream xmlStream = xmlEntry.Open();

		xmlDoc.Load(xmlStream);

		// Extract the SiPolicy file directly to the final destination, overwriting if it exists
		siPolicyEntry.ExtractToFile(SiPolicyFinalDestination, true);

		Logger.Write(GlobalVars.GetStr("DeployDriversBlockRulesRefreshPoliciesMessage"));

		CiToolHelper.RefreshPolicy();

		Logger.Write(GlobalVars.GetStr("DeployDriversBlockRulesDeployedMessage"));

		return new(Management.Initialize(null, xmlDoc));
	}

	/// <summary>
	/// Downloads the latest Microsoft Recommended Block rules from Microsoft's GitHub repository
	/// And creates a valid Code Integrity XML policy file from it.
	/// </summary>
	/// <returns>the the Microsoft recommended driver block rules base policy</returns>
	internal static PolicyFileRepresent GetDriversBlockRules()
	{
		const string name = "Microsoft Recommended Driver Block Rules";

		// Download the zip file
		byte[] fileBytes = SecHttpClient.Instance.GetByteArrayAsync(GlobalVars.MSFTRecommendedDriverBlockRulesURL)
								 .GetAwaiter().GetResult();

		// Process the zip file in memory
		using MemoryStream zipStream = new(fileBytes);
		using ZipArchive zipArchive = new(zipStream, ZipArchiveMode.Read);

		// Locate the SiPolicy_Enforced.xml file within the zip archive
		ZipArchiveEntry? xmlEntry = zipArchive.Entries.FirstOrDefault(entry => entry.Name.Equals("SiPolicy_Enforced.xml", StringComparison.OrdinalIgnoreCase)) ?? throw new FileNotFoundException("SiPolicy_Enforced.xml was not found in the downloaded zip file.");

		// Load the content of the XML file into an XmlDocument
		XmlDocument xmlDoc = new();
		using Stream xmlStream = xmlEntry.Open();
		xmlDoc.Load(xmlStream);

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(null, xmlDoc);

		// Set the policy name
		PolicySettingsManager.SetPolicyName(policyObj, name);

		// Remove the audit mode rule option from it if it has it
		policyObj = CiRuleOptions.Set(policyObj: policyObj, rulesToRemove: [OptionType.EnabledAuditMode]);

		return new(policyObj);
	}

	/// <summary>
	/// Creates and deploys an AllowMicrosoft policy based on various configurations and parameters.
	/// </summary>
	/// <param name="IsAudit">Indicates whether the policy should operate in audit mode, affecting logging behavior.</param>
	/// <param name="LogSize">Sets the size of the log for audit events, defaulting to zero if not specified.</param>
	/// <param name="deploy">Determines if the policy should be deployed after creation, enabling further actions.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled within the policy.</param>
	/// <param name="TestMode">Indicates if the policy should be created in test mode, affecting its execution.</param>
	/// <param name="deployAppControlSupplementalPolicy">Indicates if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific ID if provided, overriding the generated one for both PolicyID and BasePolicyID.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Specifies whether to deploy recommended block rules if no policy ID is provided.</param>
	/// <param name="IsAppIDTagging">Whether the created policy is an App ID Tagging type.</param>
	/// <returns>Returns the created policy</returns>
	internal static PolicyFileRepresent BuildAllowMSFT(bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules, bool IsAppIDTagging)
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

		if (IsAppIDTagging)
		{
			policyName = $"{policyName}_AppIDTagging";
		}

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(deploy);

		SiPolicy.SiPolicy policyObj = Management.Initialize(GlobalVars.AllowMicrosoftTemplatePolicyPath, null);

		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Reset PolicyID and BasePolicyID and set a new name
		policyObj = SetCiPolicyInfo.Set(
			policyObj,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null);

		if (PolicyIDToUse is not null)
		{
			policyObj.PolicyID = PolicyIDToUse;
			policyObj.BasePolicyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(policyObj.PolicyID);
		}

		// Finalize CI policy metadata
		policyObj = SetCiPolicyInfo.Set(
			policyObj,
			new Version("1.0.0.0"),
			PolicyIDToUse);

		// Apply rule options
		policyObj = CiRuleOptions.Set(
			policyObj,
			template: CiRuleOptions.PolicyTemplate.Base,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);

		// Convert it to AppIDTagging policy if it was requested
		if (IsAppIDTagging)
		{
			Dictionary<string, string> tags = [];
			tags["AllowMSFTTagKey"] = "True";

			policyObj = AppIDTagging.Convert(policyObj);
			policyObj = AppIDTagging.AddTags(policyObj, tags);
		}

		if (deploy)
		{
			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Creates and configures a DefaultWindows policy based on various parameters.
	/// options.
	/// </summary>
	/// <param name="IsAudit">Indicates whether the policy should operate in audit mode, affecting logging behavior.</param>
	/// <param name="LogSize">Sets the size limit for the event log if audit mode is enabled.</param>
	/// <param name="deploy">Determines whether the policy should be deployed after creation.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled in the policy.</param>
	/// <param name="TestMode">Indicates if the policy should be created in test mode, affecting its enforcement.</param>
	/// <param name="deployAppControlSupplementalPolicy">Specifies if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific ID if provided, overriding the generated one for both PolicyID and BasePolicyID.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Indicates whether to retrieve and deploy Microsoft recommended block rules.</param>
	/// <param name="IsAppIDTagging">Whether the created policy is an App ID Tagging type.</param>
	/// <returns>Returns the created Default Windows base policy</returns>
	internal static PolicyFileRepresent BuildDefaultWindows(bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules, bool IsAppIDTagging)
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

		if (IsAppIDTagging)
		{
			policyName = $"{policyName}_AppIDTagging";
		}

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(deploy);

		SiPolicy.SiPolicy policyObj = Management.Initialize(GlobalVars.DefaultWindowsTemplatePolicyPath, null);

		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Reset PolicyID and BasePolicyID and set a new name
		policyObj = SetCiPolicyInfo.Set(
			policyObj,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null);

		if (PolicyIDToUse is not null)
		{
			policyObj.PolicyID = PolicyIDToUse;
			policyObj.BasePolicyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(policyObj.PolicyID);
		}

		// Finalize CI policy metadata
		policyObj = SetCiPolicyInfo.Set(
			policyObj,
			new Version("1.0.0.0"),
			PolicyIDToUse);

		// Apply rule options
		policyObj = CiRuleOptions.Set(
			policyObj,
			template: CiRuleOptions.PolicyTemplate.Base,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);

		// Convert it to AppIDTagging policy if it was requested
		if (IsAppIDTagging)
		{
			Dictionary<string, string> tags = [];
			tags["DefaultWindowsTagKey"] = "True";

			policyObj = AppIDTagging.Convert(policyObj);
			policyObj = AppIDTagging.AddTags(policyObj, tags);
		}

		if (deploy)
		{
			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Gets the latest Microsoft Recommended block rules for User Mode files, removes the audit mode policy rule option and sets HVCI to strict
	/// It generates a XML file compliant with CI Policies Schema.
	/// </summary>
	/// <param name="deploy">Indicates whether the policy should be deployed after processing.</param>
	/// <exception cref="InvalidOperationException">Thrown when no XML content is found in the downloaded markdown from the Microsoft GitHub source.</exception>
	/// <returns>the created policy.</returns>
	internal static PolicyFileRepresent GetBlockRules(bool deploy)
	{
		const string policyName = "Microsoft Windows Recommended User Mode BlockList";

		Logger.Write(string.Format(
			GlobalVars.GetStr("GettingLatestPolicyFromOfficialRepoMessage"),
			policyName));

		// Download the markdown page from GitHub containing the latest Microsoft recommended block rules (User Mode)
		string msftUserModeBlockRulesAsString = SecHttpClient.Instance
				.GetStringAsync(GlobalVars.MSFTRecommendedBlockRulesURL)
				.GetAwaiter()
				.GetResult();

		// Extracted the XML content from the markdown string will saved in this variable
		string xmlContent = ExtractXmlFromHtml(msftUserModeBlockRulesAsString);

		// Load the XML content into an XmlDocument
		XmlDocument userModeBlockRulesXML = new();
		userModeBlockRulesXML.LoadXml(xmlContent);

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(
			null,
			userModeBlockRulesXML);

		policyObj = CiRuleOptions.Set(
			policyObj: policyObj,
			rulesToAdd: [OptionType.EnabledUpdatePolicyNoReboot, OptionType.DisabledScriptEnforcement],
			rulesToRemove: [OptionType.EnabledAuditMode, OptionType.EnabledAdvancedBootOptionsMenu]);

		Logger.Write(GlobalVars.GetStr("AssigningPolicyNameAndResettingPolicyIDMessage"));

		// Reset PolicyID and BasePolicyID and set a new name
		policyObj = SetCiPolicyInfo.Set(policyObj, true, policyName, null);

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
				string CurrentlyDeployedBlockRulesGUID = CurrentlyDeployedBlockRules.First().PolicyID;

				Logger.Write(string.Format(
					GlobalVars.GetStr("PolicyAlreadyDeployedUpdatingUsingSameGuidMessage"),
					policyName,
					CurrentlyDeployedBlockRulesGUID));

				// Swap the PolicyID and BasePolicyID in the current policy XML file with the one from the deployed policy
				policyObj = SetCiPolicyInfo.SetPolicyIDs(CurrentlyDeployedBlockRulesGUID, policyObj);
			}
			else
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("PolicyNotDeployedDeployingNowMessage"),
					policyName));
			}

			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	// Extracts the first <code class="lang-xml">...</code> block, decodes HTML entities and returns the raw XML text ready for XmlDocument.LoadXml.
	private static string ExtractXmlFromHtml(string content)
	{
		Match match = CodeBlockRegex().Match(content);
		if (!match.Success)
		{
			throw new InvalidOperationException("No <code class=\"lang-xml\">...</code> block found in the provided content.");
		}

		string encoded = match.Groups["xml"].Value;
		if (encoded.Length == 0)
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("NoXmlContentFoundForUserModeBlockRulesErrorMessage"));
		}

		// Decode HTML entities (&lt;, &gt;, &amp;, etc.) to obtain real XML.
		string decoded = WebUtility.HtmlDecode(encoded);

		// Basic sanity validation to catch unexpected extraction issues.
		bool appearsXml =
			decoded.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
			decoded.StartsWith("<SiPolicy", StringComparison.OrdinalIgnoreCase);

		if (!appearsXml)
		{
			throw new InvalidOperationException("Extracted content does not look like the expected XML policy.");
		}

		return decoded;
	}

	/// <summary>
	/// Creates SignedAndReputable App Control policy which is based on AllowMicrosoft template policy.
	/// It uses ISG to authorize files with good reputation.
	/// </summary>
	/// <param name="IsAudit">Indicates whether the operation should be performed in audit mode.</param>
	/// <param name="LogSize">Sets the size of the event log for recording actions taken during the process.</param>
	/// <param name="deploy">Determines if the policy should be deployed after creation.</param>
	/// <param name="RequireEVSigners">Specifies if extended validation signers are required for the policy.</param>
	/// <param name="EnableScriptEnforcement">Controls whether script enforcement is enabled in the policy.</param>
	/// <param name="TestMode">Indicates if the operation should run in test mode without making permanent changes.</param>
	/// <param name="deployAppControlSupplementalPolicy">Indicates if a supplemental policy should be deployed alongside the main policy.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific ID if provided, overriding the generated one for both PolicyID and BasePolicyID.</param>
	/// <param name="DeployMicrosoftRecommendedBlockRules">Specifies whether to retrieve and deploy Microsoft recommended block rules.</param>
	/// <returns>Returns the signed and reputable base policy</returns>
	internal static async Task<PolicyFileRepresent> BuildSignedAndReputable(bool IsAudit, double? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool deployAppControlSupplementalPolicy, string? PolicyIDToUse, bool DeployMicrosoftRecommendedBlockRules)
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

		// Get/Deploy the block rules if this base policy is not being swapped
		if (PolicyIDToUse is null && DeployMicrosoftRecommendedBlockRules)
			_ = GetBlockRules(deploy);

		SiPolicy.SiPolicy policyObj = Management.Initialize(GlobalVars.AllowMicrosoftTemplatePolicyPath, null);

		policyObj = CiRuleOptions.Set(
			policyObj,
			template: CiRuleOptions.PolicyTemplate.BaseISG,
			EnableAuditMode: IsAudit,
			RequireEVSigners: RequireEVSigners,
			ScriptEnforcement: EnableScriptEnforcement,
			TestMode: TestMode);

		Logger.Write(GlobalVars.GetStr("ResettingPolicyIdAndAssigningPolicyNameMessage"));

		// Reset PolicyID and BasePolicyID and set a new name
		policyObj = SetCiPolicyInfo.Set(
			policyObj,
			true,
			$"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}",
			null);

		if (PolicyIDToUse is not null)
		{
			policyObj.PolicyID = PolicyIDToUse;
			policyObj.BasePolicyID = PolicyIDToUse;
		}

		if (deployAppControlSupplementalPolicy)
		{
			// Supply the policy ID of the policy being deployed to this method
			SupplementalForSelf.Deploy(policyObj.PolicyID);
		}

		policyObj = SetCiPolicyInfo.Set(policyObj, new Version("1.0.0.0"), PolicyIDToUse);

		if (deploy)
		{
			await ConfigureISGServices.Configure();

			Logger.Write(GlobalVars.GetStr("ConvertingPolicyFileToCipBinaryMessage"));

			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Creates and deploys the Strict Kernel-mode base policy
	/// Since this is only Kernel-mode, we don't need to deploy the special AppControl Manager supplemental policy
	/// </summary>
	/// <param name="IsAudit">Indicates whether to add audit mode rules to the policy.</param>
	/// <param name="NoFlightRoots">Determines the filename variant used for the policy based on flight root settings.</param>
	/// <param name="deploy">Indicates whether the policy should be deployed after creation.</param>
	/// <param name="PolicyIDToUse">Allows the use of a specific ID if provided, overriding the generated one for both PolicyID and BasePolicyID.</param>
	/// <returns>the Strict Kernel-mode base policy</returns>
	internal static PolicyFileRepresent BuildStrictKernelMode(bool IsAudit, bool NoFlightRoots, bool deploy, string? PolicyIDToUse = null)
	{

		string fileName = NoFlightRoots ? "StrictKernelMode_NoFlightRoots" : "StrictKernelMode";

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		SiPolicy.SiPolicy policyObj = Management.Initialize(policyPathInResourcesDir, null);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			policyObj = CiRuleOptions.Set(policyObj: policyObj, rulesToAdd: [OptionType.EnabledAuditMode]);
		}

		if (PolicyIDToUse is not null)
		{
			policyObj = SetCiPolicyInfo.Set(policyObj, new Version("1.0.0.0"), PolicyIDToUse);
		}
		else
		{
			// Reset PolicyID and BasePolicyID
			policyObj = SetCiPolicyInfo.Set(policyObj, true, null, null);
		}

		// If it is to be deployed
		if (deploy)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("DeployingStrictKernelModePolicyMessage"),
				policyObj.PolicyID));

			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Creates the base policy responsible for blocking a large number of RMMs, Remote Monitoring and Management software.
	/// </summary>
	/// <param name="IsAudit"></param>
	/// <param name="deploy"></param>
	/// <returns></returns>
	internal static PolicyFileRepresent BuildRMMBlocking(bool IsAudit, bool deploy)
	{
		const string fileName = "Blocking RMMs - Remote Monitor and Management";

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		SiPolicy.SiPolicy policyObj = Management.Initialize(policyPathInResourcesDir, null);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			policyObj = CiRuleOptions.Set(policyObj: policyObj, rulesToAdd: [OptionType.EnabledAuditMode]);
		}

		// If it is to be deployed
		if (deploy)
		{
			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Creates the base policy for Downloads Defense Measures.
	/// </summary>
	/// <param name="IsAudit"></param>
	/// <param name="deploy"></param>
	internal static PolicyFileRepresent BuildDownloadsDefenseMeasures(bool IsAudit, bool deploy)
	{
		const string fileName = "Downloads-Defense-Measures";

		// GUID for the Downloads folder
		Guid FolderDownloads = new("374DE290-123F-4565-9164-39C4925E467B");

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		SiPolicy.SiPolicy policyObj = Management.Initialize(policyPathInResourcesDir, null);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			policyObj = CiRuleOptions.Set(policyObj: policyObj, rulesToAdd: [OptionType.EnabledAuditMode]);
		}

		IntPtr pathPtr = IntPtr.Zero;

		string? downloadsPath = null;

		try
		{
			// Get the System Downloads folder path
			int result = NativeMethods.SHGetKnownFolderPath(ref FolderDownloads, 0, IntPtr.Zero, out pathPtr);

			// This will return non-zero if running as SYSTEM
			if (result is 0) // S_OK
			{
				downloadsPath = Marshal.PtrToStringUni(pathPtr);

				if (string.IsNullOrWhiteSpace(downloadsPath))
				{
					throw new InvalidOperationException("The downloads folder path was empty, exiting.");
				}

				Logger.Write($"Downloads folder path: {downloadsPath}", LogTypeIntel.Information);
			}
			else
			{
				throw new InvalidOperationException("Failed to retrieve Downloads folder path.");
			}
		}
		finally
		{
			if (pathPtr != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(pathPtr); // Free memory allocated by SHGetKnownFolderPath
			}
		}

		string pathToUse = Path.Combine(downloadsPath, "*");

		policyObj.FileRules?.OfType<Deny>().Where(x => string.Equals(x.FilePath, "To-Be-Detected", StringComparison.OrdinalIgnoreCase))
			.ToList()
			.ForEach(x => x.FilePath = pathToUse);

		// If it is to be deployed
		if (deploy)
		{
			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}

	/// <summary>
	/// Creates the base policy for blocking dangerous script hosts and engines.
	/// </summary>
	/// <param name="IsAudit"></param>
	/// <param name="deploy"></param>
	/// <returns></returns>
	internal static PolicyFileRepresent BuildDangerousScriptBlockingPolicy(bool IsAudit, bool deploy)
	{
		const string fileName = "Dangerous-Script-Hosts-Blocking";

		// path of the policy in the app's resources directory
		string policyPathInResourcesDir = Path.Combine(AppContext.BaseDirectory, "Resources", $"{fileName}.xml");

		SiPolicy.SiPolicy policyObj = Management.Initialize(policyPathInResourcesDir, null);

		if (IsAudit)
		{
			// Add the audit mode rule option to the policy
			policyObj = CiRuleOptions.Set(policyObj: policyObj, rulesToAdd: [OptionType.EnabledAuditMode]);
		}

		// If it is to be deployed
		if (deploy)
		{
			// Deploy the CIP
			CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
		}

		return new(policyObj);
	}


	// Captures the first <code class="lang-xml">...</code> block (case-insensitive) into the named group "xml".
	// Singleline so '.' spans newlines.
	[GeneratedRegex("<code\\s+class\\s*=\\s*\"lang-xml\"\\s*>(?<xml>.*?)</code>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		6000)]
	private static partial Regex CodeBlockRegex();
}
