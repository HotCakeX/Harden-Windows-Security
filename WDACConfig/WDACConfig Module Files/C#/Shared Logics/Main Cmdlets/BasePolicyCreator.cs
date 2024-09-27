using System;
using System.Globalization;
using System.IO;
using System.Management;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

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
            DriversBlockListInfoGathering();

        }


        /// <summary>
        /// Used to supply extra information regarding Microsoft recommended driver block rules
        /// </summary>
        public static void DriversBlockListInfoGathering()
        {
            // The returned date is based on the local system's time-zone

            // Set variables
            string owner = "MicrosoftDocs";
            string repo = "windows-itpro-docs";
            string path = "windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md";
            string apiUrl = $"https://api.github.com/repos/{owner}/{repo}/commits?path={path}";

            using HttpClient httpClient = new();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36");

            try
            {
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

                if (dateString is not null)
                {
                    DateTime date = DateTime.Parse(dateString, CultureInfo.InvariantCulture);

                    Logger.Write($"The document containing the drivers block list on GitHub was last updated on {date}");
                }

                // Fetch the content of the Markdown file
                string markdownUrl = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md";
                string markdownContent = httpClient.GetStringAsync(markdownUrl).GetAwaiter().GetResult();

                // Use Regex to find the version
                var match = Regex.Match(markdownContent, @"<VersionEx>(.*?)<\/VersionEx>");
                if (match.Success)
                {
                    string version = match.Groups[1].Value;
                    Logger.Write($"The current version of Microsoft recommended drivers block list is {version}");
                }
                else
                {
                    Logger.Write("Version not found in the Markdown content.");
                }
            }
            catch (Exception ex)
            {
                Logger.Write($"An error occurred: {ex.Message}");
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


            Logger.Write("Displaying extra info about the $Name");
            DriversBlockListInfoGathering();
        }


    }
}
