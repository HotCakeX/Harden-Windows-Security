using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class BasePolicyCreator
    {
        /// <summary>
        /// Creates scheduled task that keeps the Microsoft recommended driver block rules up to date on the system
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        public static void SetAutoUpdateDriverBlockRules()
        {
            Logger.Write("Creating scheduled task for fast weekly Microsoft recommended driver block list update");

            // Initialize ManagementScope to interact with Task Scheduler's WMI namespace
            var scope = new ManagementScope(@"root\Microsoft\Windows\TaskScheduler");
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
            // Register the scheduled task. If the task's state is disabled, it will be overwritten with a new task that is enabled
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


            Logger.Write("Displaying extra info about the Microsoft recommended Drivers block list");
            _ = DriversBlockListInfoGathering();

        }

        public class DriverBlockListInfo
        {
            public string? Version { get; set; }
            public DateTime LastUpdated { get; set; }
        }


        /// <summary>
        /// Used to supply extra information regarding Microsoft recommended driver block rules
        /// </summary>
        /// <returns></returns>
        public static DriverBlockListInfo? DriversBlockListInfoGathering()
        {
            try
            {
                // The returned date is based on the local system's time-zone

                // Set variables
                string owner = "MicrosoftDocs";
                string repo = "windows-itpro-docs";
                string path = "windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md";

                string apiUrl = $"https://api.github.com/repos/{owner}/{repo}/commits?path={path}";

                using HttpClient httpClient = new();
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

                    Logger.Write($"The document containing the drivers block list on GitHub was last updated on {lastUpdated}");
                }

                // Fetch the content of the Markdown file
                string markdownUrl = GlobalVars.MSFTRecommendedDriverBlockRulesURL;
                string markdownContent = httpClient.GetStringAsync(markdownUrl).GetAwaiter().GetResult();

                // Use Regex to find the version
                string version = string.Empty;
                var match = Regex.Match(markdownContent, @"<VersionEx>(.*?)<\/VersionEx>");
                if (match.Success)
                {
                    version = match.Groups[1].Value;
                    Logger.Write($"The current version of Microsoft recommended drivers block list is {version}");
                }
                else
                {
                    Logger.Write("Version not found in the Markdown content.");
                }

                // Return an instance of DriverBlockListInfo with extracted data
                return new DriverBlockListInfo
                {
                    Version = version,
                    LastUpdated = lastUpdated
                };
            }
            catch (Exception ex)
            {
                Logger.Write($"An error occurred: {ex.Message}");

                // Return null in case of an error
                return null;
            }
        }


        /// <summary>
        /// A method to deploy the Vulnerable Driver Block List from the Microsoft servers and deploy it to the system
        /// </summary>
        /// <param name="StagingArea">The directory to use for temporary files</param>
        /// <exception cref="Exception"></exception>
        public static void DeployDriversBlockRules(string StagingArea)
        {
            // The location where the downloaded zip file will be saved
            string DownloadSaveLocation = System.IO.Path.Combine(StagingArea, "VulnerableDriverBlockList.zip");

            // The location where the zip file will be extracted
            string ZipExtractionDir = System.IO.Path.Combine(StagingArea, "VulnerableDriverBlockList");

            // The link to download the zip file
            string DriversBlockListZipDownloadLink = "https://aka.ms/VulnerableDriverBlockList";

            // Get the system drive
            string? systemDrive = Environment.GetEnvironmentVariable("SystemDrive");

            // Initialize the final destination of the SiPolicy file
            string SiPolicyFinalDestination;
            if (systemDrive != null)
            {
                // Construct the final destination of the SiPolicy file
                SiPolicyFinalDestination = System.IO.Path.Combine(systemDrive, "Windows", "System32", "CodeIntegrity", "SiPolicy.p7b");
            }
            else
            {
                throw new InvalidOperationException("SystemDrive environment variable is null");
            }

            // Download the zip file
            using (HttpClient client = new())
            {
                // Download the file synchronously
                byte[] fileBytes = client.GetByteArrayAsync(DriversBlockListZipDownloadLink).GetAwaiter().GetResult();
                File.WriteAllBytes(DownloadSaveLocation, fileBytes);
            }

            // Extract the contents of the zip file, overwriting any existing files
            System.IO.Compression.ZipFile.ExtractToDirectory(DownloadSaveLocation, ZipExtractionDir, true);

            // Get the path of the SiPolicy file
            string[] SiPolicyPaths = System.IO.Directory.GetFiles(ZipExtractionDir, "SiPolicy_Enforced.p7b", System.IO.SearchOption.AllDirectories);

            // Make sure to get only one file is there is more than one (which is unexpected)
            string SiPolicyPath = SiPolicyPaths[0];

            // If the SiPolicy file already exists, delete it
            if (File.Exists(SiPolicyFinalDestination))
            {
                File.Delete(SiPolicyFinalDestination);
            }

            // Move the SiPolicy file to the final destination, renaming it in the process
            File.Move(SiPolicyPath, SiPolicyFinalDestination);


            Logger.Write("Refreshing the system WDAC policies");
            CiToolHelper.RefreshPolicy();

            Logger.Write("SiPolicy.p7b has been deployed and policies refreshed.");


            Logger.Write("Displaying extra info about the Microsoft recommended Drivers block list");
            _ = DriversBlockListInfoGathering();
        }


        /// <summary>
        /// Downloads the latest Microsoft Recommended Block rules from Microsoft's GitHub repository
        /// And creates a valid Code Integrity XML policy file from it.
        /// </summary>
        /// <param name="StagingArea">The directory where the XML file will be saved to.</param>
        public static void GetDriversBlockRules(string StagingArea)
        {
            string name = "Microsoft Recommended Driver Block Rules";

            // Download the markdown page from GitHub containing the latest Microsoft recommended driver block rules
            string msftDriverBlockRulesAsString;
            using (HttpClient client = new())
            {
                msftDriverBlockRulesAsString = client.GetStringAsync(GlobalVars.MSFTRecommendedDriverBlockRulesURL).GetAwaiter().GetResult();
            }

            // Extracted the XML content from the markdown string will saved in this variable
            string xmlContent;

            // Regex pattern to capture XML content between ```xml and ```
            string pattern = @"```xml\s*(.*?)\s*```";

            // Extract the XML content with Regex
            Match match = Regex.Match(msftDriverBlockRulesAsString, pattern, RegexOptions.Singleline);

            if (match.Success)
            {
                // Capture the XML content
                xmlContent = match.Groups[1].Value;
            }
            else
            {
                throw new InvalidOperationException("No XML content found on the Microsoft GitHub source.");
            }

            // Load the XML content into an XmlDocument
            XmlDocument driverBlockRulesXML = new();
            driverBlockRulesXML.LoadXml(xmlContent);

            // Fix the elements
            driverBlockRulesXML = FixMissingElements(driverBlockRulesXML);

            // Generate the path for the XML file
            string xmlPath = Path.Combine(StagingArea, $"{name}.xml");

            // Save the XML content to a file
            driverBlockRulesXML.Save(xmlPath);

            CiRuleOptions.Set(filePath: xmlPath, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode]);

            Logger.Write($"Displaying extra info about the {name}");
            _ = DriversBlockListInfoGathering();

            // The final path where the XML policy file will be located
            string savePathLocation = Path.Combine(GlobalVars.UserConfigDir, $"{name}.xml");

            // Copy the result to the User Config directory at the end
            File.Copy(xmlPath, savePathLocation, true);

            Logger.Write($"The policy file was created and saved to {savePathLocation}");
        }



        /// <summary>
        /// Creates a base policy based on the AllowMicrosoft template
        /// </summary>
        /// <param name="StagingArea"></param>
        /// <param name="IsAudit"></param>
        /// <param name="LogSize"></param>
        /// <param name="deploy"></param>
        /// <param name="RequireEVSigners"></param>
        /// <param name="EnableScriptEnforcement"></param>
        /// <param name="TestMode"></param>
        public static void BuildAllowMSFT(string StagingArea, bool IsAudit, ulong? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool? deployAppControlSupplementalPolicy)
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

            // Path only used during staging area processing
            string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");

            string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

            string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

            GetBlockRules(StagingArea, deploy, false);


            Logger.Write("Copying the AllowMicrosoft.xml from Windows directory to the Staging Area");

            File.Copy(@"C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml", tempPolicyPath, true);



            Logger.Write("Resetting the policy ID and assigning policy name");

            // Get the policy ID of the policy being created
            string policyID = WDACConfig.SetCiPolicyInfo.Set(tempPolicyPath, true, $"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}", null, null);

            if (deployAppControlSupplementalPolicy == true)
            {
                // Supply the policy ID of the policy being deployed to this method
                SupplementalForSelf.Deploy(StagingArea, policyID);
            }

            SetCiPolicyInfo.Set(tempPolicyPath, new Version("1.0.0.0"));

            CiRuleOptions.Set(
                tempPolicyPath,
                template: CiRuleOptions.PolicyTemplate.Base,
                EnableAuditMode: IsAudit,
                RequireEVSigners: RequireEVSigners,
                ScriptEnforcement: EnableScriptEnforcement,
                TestMode: TestMode);


            if (deploy)
            {

                Logger.Write("Converting the policy file to .CIP binary");

                PolicyToCIPConverter.Convert(tempPolicyPath, tempPolicyCIPPath);

                CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
            }

            File.Copy(tempPolicyPath, finalPolicyPath, true);


        }



        /// <summary>
        /// Gets the latest Microsoft Recommended block rules for User Mode files, removes the audit mode policy rule option and sets HVCI to strict
        /// It generates a XML file compliant with CI Policies Schema.
        /// </summary>
        /// <param name="StagingArea"></param>
        public static void GetBlockRules(string StagingArea, bool deploy, bool? deployAppControlSupplementalPolicy)
        {

            string policyName = "Microsoft Windows Recommended User Mode BlockList";

            Logger.Write($"Getting the latest {policyName} from the official Microsoft GitHub repository");

            // Download the markdown page from GitHub containing the latest Microsoft recommended block rules (User Mode)
            string msftUserModeBlockRulesAsString;
            using (HttpClient client = new())
            {
                msftUserModeBlockRulesAsString = client.GetStringAsync(GlobalVars.MSFTRecommendedBlockRulesURL).GetAwaiter().GetResult();
            }

            // Extracted the XML content from the markdown string will saved in this variable
            string xmlContent;

            // Regex pattern to capture XML content between ```xml and ```
            string pattern = @"```xml\s*(.*?)\s*```";

            // Extract the XML content with Regex
            Match match = Regex.Match(msftUserModeBlockRulesAsString, pattern, RegexOptions.Singleline);

            if (match.Success)
            {
                // Capture the XML content
                xmlContent = match.Groups[1].Value;
            }
            else
            {
                throw new InvalidOperationException("No XML content found on the Microsoft GitHub source for Microsoft Recommended User Mode Block Rules.");
            }

            // Load the XML content into an XmlDocument
            XmlDocument userModeBlockRulesXML = new();
            userModeBlockRulesXML.LoadXml(xmlContent);

            // Fix the elements
            userModeBlockRulesXML = FixMissingElements(userModeBlockRulesXML);

            // Path only used during staging area processing
            string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");

            string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");


            // Save the XML content to a file
            userModeBlockRulesXML.Save(tempPolicyPath);


            CiRuleOptions.Set(filePath: tempPolicyPath, rulesToAdd: [CiRuleOptions.PolicyRuleOptions.EnabledUpdatePolicyNoReboot, CiRuleOptions.PolicyRuleOptions.DisabledScriptEnforcement], rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode, CiRuleOptions.PolicyRuleOptions.EnabledAdvancedBootOptionsMenu]);

            Logger.Write("Assigning policy name and resetting policy ID");

            // Get the policyID of the policy being created
            string policyID = SetCiPolicyInfo.Set(tempPolicyPath, true, policyName, null, null);


            string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

            if (deploy)
            {

                Logger.Write($"Checking if the {policyName} policy is already deployed");


                List<CiPolicyInfo> CurrentlyDeployedBlockRules = CiToolHelper.GetPolicies(false, true, false).Where(policy => string.Equals(policy.FriendlyName, policyName, StringComparison.OrdinalIgnoreCase)).ToList();

                if (CurrentlyDeployedBlockRules.Count > 0)
                {
                    string CurrentlyDeployedBlockRulesGUID = CurrentlyDeployedBlockRules.First().PolicyID!;

                    Logger.Write($"{policyName} policy is already deployed, updating it using the same GUID which is {CurrentlyDeployedBlockRulesGUID}.");
                    PolicyEditor.EditGuids(CurrentlyDeployedBlockRulesGUID, new FileInfo(tempPolicyPath));

                }
                else
                {
                    Logger.Write($"{policyName} policy is not deployed, deploying it now.");
                }

                PolicyToCIPConverter.Convert(tempPolicyPath, tempPolicyCIPPath);

                CiToolHelper.UpdatePolicy(tempPolicyCIPPath);

            }

            File.Copy(tempPolicyPath, finalPolicyPath, true);


        }



        /// <summary>
        /// Creates SignedAndReputable WDAC policy which is based on AllowMicrosoft template policy.
        /// It uses ISG to authorize files with good reputation.
        /// </summary>
        /// <param name="StagingArea"></param>
        /// <param name="IsAudit"></param>
        /// <param name="LogSize"></param>
        /// <param name="deploy"></param>
        /// <param name="RequireEVSigners"></param>
        /// <param name="EnableScriptEnforcement"></param>
        /// <param name="TestMode"></param>
        public static void BuildSignedAndReputable(string StagingArea, bool IsAudit, ulong? LogSize, bool deploy, bool RequireEVSigners, bool EnableScriptEnforcement, bool TestMode, bool? deployAppControlSupplementalPolicy)
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

            // Path only used during staging area processing
            string tempPolicyPath = Path.Combine(StagingArea, $"{policyName}.xml");

            string tempPolicyCIPPath = Path.Combine(StagingArea, $"{policyName}.cip");

            string finalPolicyPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

            GetBlockRules(StagingArea, deploy, false);


            Logger.Write("Copying the AllowMicrosoft.xml from Windows directory to the Staging Area");

            File.Copy(@"C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml", tempPolicyPath, true);


            CiRuleOptions.Set(
tempPolicyPath,
template: CiRuleOptions.PolicyTemplate.BaseISG,
EnableAuditMode: IsAudit,
RequireEVSigners: RequireEVSigners,
ScriptEnforcement: EnableScriptEnforcement,
TestMode: TestMode);



            Logger.Write("Resetting the policy ID and assigning policy name");

            // Get the policyID of the policy being created
            string policyID = SetCiPolicyInfo.Set(tempPolicyPath, true, $"{policyName} - {DateTime.Now.ToString("MM-dd-yyyy", CultureInfo.InvariantCulture)}", null, null);

            if (deployAppControlSupplementalPolicy == true)
            {
                SupplementalForSelf.Deploy(StagingArea, policyID);
            }

            SetCiPolicyInfo.Set(tempPolicyPath, new Version("1.0.0.0"));


            if (deploy)
            {

                Logger.Write("Converting the policy file to .CIP binary");

                PolicyToCIPConverter.Convert(tempPolicyPath, tempPolicyCIPPath);

                CiToolHelper.UpdatePolicy(tempPolicyCIPPath);
            }

            File.Copy(tempPolicyPath, finalPolicyPath, true);


        }



        /// <summary>
        /// Make sure PolicyType attribute, BasePolicyID node and PolicyID nodes exist and remove PolicyTypeID node if it exists
        /// </summary>
        /// <param name="XML"> The XML document to modify, the modified XML document will be returned at the end </param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static XmlDocument FixMissingElements(XmlDocument XML)
        {

            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(XML.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Get SiPolicy node
            XmlNode siPolicyNode = XML.SelectSingleNode("ns:SiPolicy", namespaceManager)
                ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            string? policyType = siPolicyNode.Attributes?["PolicyType"]?.Value;

            if (policyType is null)
            {
                // Create PolicyType attribute and set it to "Base Policy"
                XmlAttribute newPolicyTypeAttribute = XML.CreateAttribute("PolicyType");
                newPolicyTypeAttribute.Value = "Base Policy";
                _ = siPolicyNode.Attributes!.Append(newPolicyTypeAttribute);
            }


            // Get the nodes
            XmlNode? policyIDNode = siPolicyNode.SelectSingleNode("ns:PolicyID", namespaceManager);
            XmlNode? basePolicyIDNode = siPolicyNode.SelectSingleNode("ns:BasePolicyID", namespaceManager);
            XmlNode? policyTypeIDNode = siPolicyNode.SelectSingleNode("ns:PolicyTypeID", namespaceManager);

            // Generate a new GUID
            Guid newRandomGUID = System.Guid.NewGuid();

            // Convert it to string
            string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";


            if (basePolicyIDNode is null)
            {
                // Create the node
                XmlElement newBasePolicyIDNode = XML.CreateElement("BasePolicyID", "urn:schemas-microsoft-com:sipolicy");

                // Set its value to match PolicyID because this is a Base policy
                newBasePolicyIDNode.InnerText = newRandomGUIDString;

                // Append the new BasePolicyID node to the SiPolicy node
                _ = siPolicyNode.AppendChild(newBasePolicyIDNode);
            }


            if (policyIDNode is null)
            {
                // Create the node
                XmlElement newPolicyIDNode = XML.CreateElement("PolicyID", "urn:schemas-microsoft-com:sipolicy");

                // Set its value to match PolicyID because this is a Base policy
                newPolicyIDNode.InnerText = newRandomGUIDString;

                // Append the new BasePolicyID node to the SiPolicy node
                _ = siPolicyNode.AppendChild(newPolicyIDNode);
            }

            if (policyTypeIDNode is not null)
            {
                // Remove the policyTypeIDNode from its parent (siPolicyNode)
                _ = siPolicyNode.RemoveChild(policyTypeIDNode);
            }

            return XML;
        }


    }
}
