using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using WDACConfig.IntelGathering;


namespace WDACConfig.Pages
{

    public sealed partial class AllowNewAppsStart : Page
    {

        // The user selected XML base policy path
        private static string? selectedXMLFilePath;

        // The user selected Supplemental policy path
        private static string? selectedSupplementalPolicyName;

        // The user selected directories to scan
        private readonly static List<string> selectedDirectoriesToScan = [];

        // The user selected deploy button status
        private bool deployPolicy = true;

        // The user selected scan level
        private ScanLevels scanLevel = ScanLevels.FilePublisher;

        // Only the logs generated after this time will be shown
        // It will be set when user moves from Step1 to Step2
        private DateTime? LogsScanStartTime;


        // Paths for the entire operation of this page
        private static DirectoryInfo? stagingArea;
        private string? tempBasePolicyPath;
        private string? AuditModeCIP;
        private string? EnforcedModeCIP;

        // Save the current log size that is user input from the number box UI element
        private ulong LogSize;

        // HashSet to store the output of both local files and event logs scans
        private readonly static HashSet<FileIdentity> fileIdentities = new(new FileIdentityComparer());


        #region

        // To store the FileIdentities displayed on the Local Files DataGrid
        public ObservableCollection<FileIdentity> LocalFilesFileIdentities { get; set; }

        // Store all outputs for searching, used as a temporary storage for filtering
        // If ObservableCollection were used directly, any filtering or modification could remove items permanently
        // from the collection, making it difficult to reset or apply different filters without re-fetching data.
        public List<FileIdentity> LocalFilesAllFileIdentities;


        // To store the FileIdentities displayed on the Event Logs DataGrid
        public ObservableCollection<FileIdentity> EventLogsFileIdentities { get; set; }

        // Store all outputs for searching, used as a temporary storage for filtering
        // If ObservableCollection were used directly, any filtering or modification could remove items permanently
        // from the collection, making it difficult to reset or apply different filters without re-fetching data.
        public List<FileIdentity> EventLogsAllFileIdentities;

        #endregion


        // A static instance of the AllowNewAppsStart class which will hold the single, shared instance of the page
        private static AllowNewAppsStart? _instance;


        public AllowNewAppsStart()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Assign this instance to the static field
            _instance = this;

            // Initially disable Steps 2 and 3
            SetBorderStyles(Step1Border);
            DisableStep2();
            DisableStep3();


            // Get the user configuration for unsigned policy path and fill in the text box
            SelectedXMLFilePathTextBox.Text = UserConfiguration.Get().UnsignedPolicyPath;

            // Initialize the collections
            EventLogsAllFileIdentities = [];
            EventLogsFileIdentities = [];
            LocalFilesAllFileIdentities = [];
            LocalFilesFileIdentities = [];

            // Initially set the log size in the number box to the current size of the Code Integrity Operational log
            double currentLogSize = EventLogUtility.GetCurrentLogSize();
            LogSizeNumberBox.Value = currentLogSize;
            LogSize = Convert.ToUInt64(currentLogSize);
        }


        // Public property to access the singleton instance from other classes
        public static AllowNewAppsStart Instance => _instance ?? throw new InvalidOperationException("AllowNewAppsStart is not initialized.");



        #region Steps management

        private void DisableStep1()
        {
            BrowseForXMLPolicyButton.IsEnabled = false;
            GoToStep2Button.IsEnabled = false;
            SupplementalPolicyNameTextBox.IsEnabled = false;
            SelectedXMLFilePathTextBox.IsEnabled = false;
            Step1Grid.Opacity = 0.5;
            ResetBorderStyles(Step1Border);
            Step1InfoBar.IsOpen = false;
            Step1InfoBar.Message = null;
            LogSizeNumberBox.IsEnabled = false;
        }

        private void EnableStep1()
        {
            BrowseForXMLPolicyButton.IsEnabled = true;
            GoToStep2Button.IsEnabled = true;
            SupplementalPolicyNameTextBox.IsEnabled = true;
            SelectedXMLFilePathTextBox.IsEnabled = true;
            Step1Grid.Opacity = 1;
            SetBorderStyles(Step1Border);
            LogSizeNumberBox.IsEnabled = true;
        }

        private void DisableStep2()
        {
            BrowseForFoldersButton.IsEnabled = false;
            GoToStep3Button.IsEnabled = false;
            Step2Grid.Opacity = 0.5;
            ResetBorderStyles(Step2Border);
            Step2InfoBar.IsOpen = false;
            Step2InfoBar.Message = null;
        }

        private void EnableStep2()
        {
            BrowseForFoldersButton.IsEnabled = true;
            Step2Grid.Opacity = 1;
            GoToStep3Button.IsEnabled = true;
            SetBorderStyles(Step2Border);
        }

        private void DisableStep3()
        {
            DeployToggleButton.IsEnabled = false;
            ScanLevelComboBox.IsEnabled = false;
            CreatePolicyButton.IsEnabled = false;
            Step3Grid.Opacity = 0.5;
            ResetBorderStyles(Step3Border);
            Step3InfoBar.IsOpen = false;
            Step3InfoBar.Message = null;
        }

        private void EnableStep3()
        {
            DeployToggleButton.IsEnabled = true;
            ScanLevelComboBox.IsEnabled = true;
            CreatePolicyButton.IsEnabled = true;
            Step3Grid.Opacity = 1;
            SetBorderStyles(Step3Border);
        }

        #endregion


        /// <summary>
        /// Step 1 validation
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private async void GoToStep2Button_Click(object sender, RoutedEventArgs e)
        {

            bool errorOccurred = false;

            try
            {
                Step1ProgressRing.IsActive = true;
                GoToStep2Button.IsEnabled = false;
                ResetStepsButton.IsEnabled = false;


                // Ensure the text box for policy file name is filled
                if (string.IsNullOrWhiteSpace(SupplementalPolicyNameTextBox.Text))
                {
                    throw new InvalidOperationException("You need to select a name for the Supplemental Policy");
                }
                else
                {
                    selectedSupplementalPolicyName = SupplementalPolicyNameTextBox.Text;
                }

                // Ensure user selected a XML policy file path
                if (string.IsNullOrWhiteSpace(SelectedXMLFilePathTextBox.Text))
                {
                    throw new InvalidOperationException("You need to select a XML policy file path");
                }
                else
                {
                    selectedXMLFilePath = SelectedXMLFilePathTextBox.Text;
                }


                // Create the required directory and file paths in step 1
                stagingArea = StagingArea.NewStagingArea("AllowNewApps");
                tempBasePolicyPath = Path.Combine(stagingArea.FullName, "BasePolicy.XML");
                AuditModeCIP = Path.Combine(stagingArea.FullName, "BaseAudit.cip");

                // Make sure it stays unique because it's being put outside of the StagingArea and we don't want any other command to remove or overwrite it
                EnforcedModeCIP = Path.Combine(GlobalVars.UserConfigDir, $"BaseEnforced-{Guid.NewGuid().ToString().Replace("-", "")}.cip");

                Step1InfoBar.IsOpen = true;
                Step1InfoBar.Message = "Deploying the selected policy in Audit mode, please wait";

                // Execute the main tasks of step 1
                await Task.Run(() =>
                {

                    // Instantiate the policy
                    CodeIntegrityPolicy codeIntegrityPolicy = new(selectedXMLFilePath, null);

                    // Get all deployed base policies
                    List<CiPolicyInfo> allDeployedBasePolicies = CiToolHelper.GetPolicies(false, true, false);

                    // Get all the deployed base policyIDs
                    List<string?> CurrentlyDeployedBasePolicyIDs = allDeployedBasePolicies.Select(p => p.BasePolicyID).ToList();

                    // Trim the curly braces from the policyID
                    string trimmedPolicyID = codeIntegrityPolicy.PolicyID.TrimStart('{').TrimEnd('}');

                    // Make sure the selected policy is a base and that it is deployed on the system
                    if (!CurrentlyDeployedBasePolicyIDs.Any(id => string.Equals(id, trimmedPolicyID, StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new InvalidOperationException($"The selected policy file {selectedXMLFilePath} is not deployed on the system or it's not a base policy");
                    }

                    // Make sure the policy is not signed
                    CiPolicyInfo detectedBasePolicy = allDeployedBasePolicies.First(p => string.Equals(p.PolicyID, trimmedPolicyID, StringComparison.OrdinalIgnoreCase));

                    if (detectedBasePolicy.IsSignedPolicy)
                    {
                        throw new InvalidOperationException("The selected policy is signed. Signed policies are not supported yet.");
                    }

                    // Creating a copy of the original policy in the Staging Area so that the original one will be unaffected
                    File.Copy(selectedXMLFilePath, tempBasePolicyPath, true);

                    // Create audit mode CIP
                    CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode]);
                    PolicyToCIPConverter.Convert(tempBasePolicyPath, AuditModeCIP);

                    // Create Enforced mode CIP
                    CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode]);
                    PolicyToCIPConverter.Convert(tempBasePolicyPath, EnforcedModeCIP);

                    Logger.Write("Creating Enforced Mode SnapBack guarantee");
                    SnapBackGuarantee.Create(EnforcedModeCIP);

                    Logger.Write("Deploying the Audit mode policy");
                    CiToolHelper.UpdatePolicy(AuditModeCIP);

                    Logger.Write("The Base policy has been Re-Deployed in Audit Mode");

                    EventLogUtility.SetLogSize(LogSize);

                });


                DisableStep1();
                EnableStep2();
                DisableStep3();

                LogsScanStartTime = DateTime.Now;
            }
            catch
            {
                errorOccurred = true;

                throw;  // Re-throw the same exception, preserving the stack trace
            }
            finally
            {
                Step1ProgressRing.IsActive = false;
                ResetStepsButton.IsEnabled = true;

                // Only re-enable the button if errors occurred, otherwise we don't want to override the work that DisableStep1() method does
                if (errorOccurred)
                {
                    GoToStep2Button.IsEnabled = true;
                    Step1InfoBar.Message = null;
                    Step1InfoBar.IsOpen = false;
                }
            }
        }


        /// <summary>
        /// Step 2 validation
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void GoToStep3Button_Click(object sender, RoutedEventArgs e)
        {

            bool errorsOccurred = false;

            try
            {
                Step2ProgressRing.IsActive = true;
                GoToStep3Button.IsEnabled = false;
                ResetStepsButton.IsEnabled = false;

                // Enable the DataGrid pages so user can select the logs
                AllowNewApps.Instance.EnableAllowNewAppsNavigationItem("LocalFiles");
                AllowNewApps.Instance.EnableAllowNewAppsNavigationItem("EventLogs");

                Step2InfoBar.IsOpen = true;

                await Task.Run(() =>
                {

                    // Deploy the base policy in enforced mode before proceeding with scans
                    if (EnforcedModeCIP is null)
                    {
                        throw new InvalidOperationException("Enforced mode CIP file could not be found");
                    }


                    _ = DispatcherQueue.TryEnqueue(() =>
                    {
                        Step2InfoBar.Message = "Deploying the Enforced mode policy.";
                    });


                    Logger.Write("Deploying the Enforced mode policy.");
                    CiToolHelper.UpdatePolicy(EnforcedModeCIP);

                    // Delete the enforced mode CIP file after deployment
                    File.Delete(EnforcedModeCIP);

                    // Remove the snap back guarantee task and related .bat file after successfully re-deploying the Enforced mode policy
                    SnapBackGuarantee.Remove();

                    // Check if user selected directories to be scanned
                    if (selectedDirectoriesToScan.Count > 0)
                    {

                        _ = DispatcherQueue.TryEnqueue(() =>
                        {
                            Step2InfoBar.Message = "Scanning the selected directories";
                        });


                        DirectoryInfo[] selectedDirectories = [];

                        // Convert user selected folder paths that are strings to DirectoryInfo objects
                        selectedDirectories = selectedDirectoriesToScan.Select(dir => new DirectoryInfo(dir)).ToArray();

                        // Get all of the AppControl compatible files from user selected directories
                        List<FileInfo> DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, null, null);

                        // Scan all of the detected files from the user selected directories
                        HashSet<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(DetectedFilesInSelectedDirectories);

                        // Add the results of the directories scans to the DataGrid
                        foreach (FileIdentity item in LocalFilesResults)
                        {
                            _ = DispatcherQueue.TryEnqueue(() =>
                            {
                                LocalFilesFileIdentities.Add(item);
                                LocalFilesAllFileIdentities.Add(item);

                            });
                        }
                    }

                });

                // Update the total logs on that page once we add data to it from here
                // If the page is not loaded yet then this won't run since it's nullable. Upon switching to that page however the OnNavigateTo event will update the count.
                // If the page is already loaded and user is sitting on it, that means instance is initialized so we can update it in real time from here.
                AllowNewAppsLocalFilesDataGrid.Instance?.UpdateTotalLogs();


                Step2InfoBar.Message = "Scanning the event logs";

                // Check for available logs

                // Grab the App Control Logs
                HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

                // Filter the logs and keep only ones generated after audit mode policy was deployed
                await Task.Run(() =>
                {
                    Output = Output
                        .Where(fileIdentity => fileIdentity.TimeCreated >= LogsScanStartTime)
                        .ToHashSet();
                });

                // If any logs were generated since audit mode policy was deployed
                if (Output.Count > 0)
                {

                    // Add the event logs to the DataGrid
                    foreach (FileIdentity item in Output)
                    {
                        EventLogsFileIdentities.Add(item);
                        EventLogsAllFileIdentities.Add(item);
                    }
                }

                // Update the total logs on that page once we add data to it from here
                // If the page is not loaded yet then this won't run since it's nullable. Upon switching to that page however the OnNavigateTo event will update the count.
                // If the page is already loaded and user is sitting on it, that means instance is initialized so we can update it in real time from here.
                AllowNewAppsEventLogsDataGrid.Instance?.UpdateTotalLogs();


                DisableStep1();
                DisableStep2();
                EnableStep3();
            }
            catch
            {
                errorsOccurred = true;

                throw;
            }
            finally
            {
                Step2ProgressRing.IsActive = false;
                ResetStepsButton.IsEnabled = true;

                // Only perform these actions if an error occurred
                if (errorsOccurred)
                {
                    GoToStep3Button.IsEnabled = true;

                    // When an error occurrs before the disable methods run, we need to clear them manually here
                    Step2InfoBar.IsOpen = false;
                    Step2InfoBar.Message = null;
                }
            }
        }


        /// <summary>
        /// Steps Reset
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void ResetStepsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {

                ResetProgressRing.IsActive = true;

                // Delete the enforced mode CIP file from the user config directory if it exists
                if (Path.Exists(EnforcedModeCIP))
                {
                    File.Delete(EnforcedModeCIP);
                }

                // Disable all steps
                DisableStep1();
                DisableStep2();
                DisableStep3();

                // Clear the DataGrids and their respective search/filter-related lists
                LocalFilesFileIdentities.Clear();
                LocalFilesAllFileIdentities.Clear();
                EventLogsFileIdentities.Clear();
                EventLogsAllFileIdentities.Clear();

                // reset the class variables back to their default states
                selectedDirectoriesToScan.Clear();
                deployPolicy = true;
                selectedSupplementalPolicyName = null;
                selectedXMLFilePath = null;
                LogsScanStartTime = null;

                LogSizeNumberBox.Value = EventLogUtility.GetCurrentLogSize();

                // Disable the data grids access
                AllowNewApps.Instance.DisableAllowNewAppsNavigationItem("LocalFiles");
                AllowNewApps.Instance.DisableAllowNewAppsNavigationItem("EventLogs");

                // Reset the UI inputs back to their default states
                DeployToggleButton.IsChecked = true;
                SelectedDirectoriesTextBox.Text = null;
                SelectedXMLFilePathTextBox.Text = null;
                SupplementalPolicyNameTextBox.Text = null;
                ScanLevelComboBox.SelectedIndex = 0;

                // Run the main reset tasks on a different thread
                await Task.Run(() =>
                {

                    // Deploy the base policy in enforced mode if user advanced to that step
                    if (Path.Exists(EnforcedModeCIP))
                    {
                        Logger.Write("Deploying the Enforced mode policy because user decided to reset the operation");
                        CiToolHelper.UpdatePolicy(EnforcedModeCIP);
                    }

                    // Remove the snap back guarantee task if it exists
                    SnapBackGuarantee.Remove();
                });

                // Get the user configuration for unsigned policy path and fill in the text box
                SelectedXMLFilePathTextBox.Text = UserConfiguration.Get().UnsignedPolicyPath;

            }
            finally
            {
                // Enable the step1 for new operation
                EnableStep1();
                ResetProgressRing.IsActive = false;
            }
        }



        private void ClearSelectedDirectoriesButton_Click(object sender, RoutedEventArgs e)
        {
            // Clear the text box on the UI
            SelectedDirectoriesTextBox.Text = string.Empty;

            // Clear the list of selected directories
            selectedDirectoriesToScan.Clear();
        }


        private void DeployToggleButton_Checked(object sender, RoutedEventArgs e)
        {
            deployPolicy = true;

        }


        private void DeployToggleButton_Unchecked(object sender, RoutedEventArgs e)
        {
            deployPolicy = false;
        }


        private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ScanLevelComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                string selectedText = selectedItem.Content.ToString()!;

                if (!Enum.TryParse(selectedText, out scanLevel))
                {
                    throw new InvalidOperationException($"{selectedText} is not a valid Scan Level");
                }
            }
        }

        private void BrowseForFoldersButton_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFolder = FileSystemPicker.ShowDirectoryPicker();
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                selectedDirectoriesToScan.Add(selectedFolder);

                // Update the text box on the UI
                SelectedDirectoriesTextBox.Text = string.Join(Environment.NewLine, selectedDirectoriesToScan);
            }
        }

        private void BrowseForXMLPolicyButton_Click(object sender, RoutedEventArgs e)
        {

            string? selectedFile = FileSystemPicker.ShowFilePicker(
            "Select an XML file",
            ("XML Files", "*.xml"));

            if (!string.IsNullOrWhiteSpace(selectedFile))
            {
                // The extra validations are required since user can provide path in the text box directly
                if (File.Exists(selectedFile) && (Path.GetExtension(selectedFile).Equals(".xml", StringComparison.OrdinalIgnoreCase)))
                {
                    // Store the selected XML file path
                    selectedXMLFilePath = selectedFile;

                    // Update the TextBox with the selected XML file path
                    SelectedXMLFilePathTextBox.Text = selectedFile;
                }
                else
                {
                    throw new InvalidOperationException($"Selected item '{selectedFile}' is not a valid XML file path");
                }
            }

        }


        #region Manage active step border

        private static void SetBorderStyles(Border border)
        {
            // Create the brush
            SolidColorBrush goldenrodBrush = new(Colors.Goldenrod);

            // apply the styles to the border
            border.BorderBrush = goldenrodBrush;
            border.BorderThickness = new Thickness(1);
        }

        private static void ResetBorderStyles(Border border)
        {
            // Reset the BorderBrush and BorderThickness to their default values
            border.BorderBrush = null;
            border.BorderThickness = new Thickness(0);
        }

        #endregion


        /// <summary>
        /// Event handler for the Create Policy button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void CreatePolicyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Disable the CreatePolicy button for the duration of the operation
                CreatePolicyButton.IsEnabled = false;

                ResetStepsButton.IsEnabled = false;

                Step3InfoBar.IsOpen = true;
                Step3InfoBar.Message = "Creating the policy using any available event logs or file scan results in other tabs.";


                // Check if there are items for the local file scans DataGrid
                if (LocalFilesFileIdentities.Count > 0)
                {
                    // convert every selected item to FileIdentity and store it in the list
                    foreach (FileIdentity item in LocalFilesFileIdentities)
                    {
                        _ = fileIdentities.Add(item);
                    }
                }

                // Check if there are selected items for the Event Logs scan DataGrid
                if (EventLogsFileIdentities.Count > 0)
                {
                    // convert every selected item to FileIdentity and store it in the list
                    foreach (FileIdentity item in EventLogsFileIdentities)
                    {
                        _ = fileIdentities.Add(item);
                    }
                }


                // If there are no logs to create a Supplemental policy with
                if (fileIdentities.Count == 0)
                {
                    Step3InfoBar.Severity = InfoBarSeverity.Warning;
                    Step3InfoBar.Message = "There are no logs or files in any data grids to create a Supplemental policy for.";
                    return;
                }


                await Task.Run(() =>
                {

                    if (stagingArea is null)
                    {
                        throw new InvalidOperationException("Staging Area wasn't found");
                    }

                    // Get the path to an empty policy file
                    string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

                    // Separate the signed and unsigned data
                    FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. fileIdentities], level: scanLevel);

                    // Insert the data into the empty policy file
                    XMLOps.Initiate(DataPackage, EmptyPolicyPath);

                    string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{selectedSupplementalPolicyName}.xml");

                    // Instantiate the user selected Base policy - To get its BasePolicyID
                    CodeIntegrityPolicy codeIntegrityPolicy = new(selectedXMLFilePath, null);

                    // Set the BasePolicyID of our new policy to the one from user selected policy
                    string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, selectedSupplementalPolicyName, codeIntegrityPolicy.BasePolicyID, null);

                    // Configure policy rule options
                    CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

                    // Set policy version
                    SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

                    // Copying the policy file to the User Config directory - outside of the temporary staging area
                    File.Copy(EmptyPolicyPath, OutputPath, true);


                    // If user selected to deploy the policy
                    if (deployPolicy)
                    {
                        string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                        PolicyToCIPConverter.Convert(OutputPath, CIPPath);

                        CiToolHelper.UpdatePolicy(CIPPath);
                    }

                });


                Step3InfoBar.Severity = InfoBarSeverity.Success;
                Step3InfoBar.IsClosable = true;
                Step3InfoBar.Message = deployPolicy ? "Successfully created and deployed the policy." : "Successfully created the policy.";

            }
            finally
            {
                CreatePolicyButton.IsEnabled = true;
                ResetStepsButton.IsEnabled = true;
            }
        }


        /// <summary>
        /// Event handler for the LogSize number box
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private void LogSizeNumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
        {
            // Check if the value changed successfully.
            if (!double.IsNaN(args.NewValue))
            {
                // Handle the new value.
                double newValue = args.NewValue;

                // Convert the value from megabytes to bytes
                double bytesValue = newValue * 1024 * 1024;

                // Convert the value to ulong
                LogSize = Convert.ToUInt64(bytesValue);
            }
            else
            {
                throw new InvalidOperationException("Invalid input detected.");
            }
        }

    }
}
