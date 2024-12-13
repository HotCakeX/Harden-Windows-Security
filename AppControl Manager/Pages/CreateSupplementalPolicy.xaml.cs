using AppControlManager.IntelGathering;
using AppControlManager.Logging;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AppControlManager.Pages
{

    public sealed partial class CreateSupplementalPolicy : Page
    {

        // A static instance of the CreateSupplementalPolicy class which will hold the single, shared instance of the page
        private static CreateSupplementalPolicy? _instance;

        public CreateSupplementalPolicy()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Assign this instance to the static field
            _instance = this;
        }


        // Public property to access the singleton instance from other classes
        public static CreateSupplementalPolicy Instance => _instance ?? throw new InvalidOperationException("CreateSupplementalPolicy is not initialized.");



        #region Files and Folders scan

        // Selected File Paths
        private readonly HashSet<string> filesAndFoldersFilePaths = [];

        // Selected Folder Paths
        private readonly HashSet<string> filesAndFoldersFolderPaths = [];

        // Selected Base policy path
        private string? filesAndFoldersBasePolicyPath;

        // Selected Supplemental policy name
        private string? filesAndFoldersSupplementalPolicyName;

        // The user selected scan level
        private ScanLevels filesAndFoldersScanLevel = ScanLevels.FilePublisher;

        private bool filesAndFoldersDeployButton;

        // Used to store the scan results and as the source for the results DataGrids
        internal ObservableCollection<FileIdentity> filesAndFoldersScanResults = [];
        internal List<FileIdentity> filesAndFoldersScanResultsList = [];


        /// <summary>
        /// Browse for Files - Settings Card Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFilesSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "Any file (*.*)|*.*";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    _ = filesAndFoldersFilePaths.Add(file);

                    // Append the new file to the TextBox, followed by a newline
                    FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;

                }
            }

            // Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
            FilesAndFoldersBrowseForFilesButton_Flyout.ShowAt(FilesAndFoldersBrowseForFilesSettingsCard);

        }

        /// <summary>
        /// Browse for Files - Button Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFilesButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "Any file (*.*)|*.*";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    _ = filesAndFoldersFilePaths.Add(file);

                    // Append the new file to the TextBox, followed by a newline
                    FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;

                }
            }
        }


        /// <summary>
        /// Browse for Folders - Settings Card Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFoldersSettingsCard_Click(object sender, RoutedEventArgs e)
        {

            List<string>? selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

            if (selectedDirectories is not null && selectedDirectories.Count > 0)
            {
                foreach (string dir in selectedDirectories)
                {
                    _ = filesAndFoldersFolderPaths.Add(dir);

                    // Append the new directory to the TextBox, followed by a newline
                    FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text += dir + Environment.NewLine;

                }
            }

            // Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
            FilesAndFoldersBrowseForFoldersButton_FlyOut.ShowAt(FilesAndFoldersBrowseForFoldersSettingsCard);
        }


        /// <summary>
        /// Browse for Folders - Button Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFoldersButton_Click(object sender, RoutedEventArgs e)
        {
            List<string>? selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

            if (selectedDirectories is not null && selectedDirectories.Count > 0)
            {
                foreach (string dir in selectedDirectories)
                {
                    _ = filesAndFoldersFolderPaths.Add(dir);

                    // Append the new directory to the TextBox, followed by a newline
                    FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text += dir + Environment.NewLine;

                }
            }
        }


        /// <summary>
        /// Browse for Base Policy - Settings Card Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                filesAndFoldersBasePolicyPath = selectedFile;

            }
        }


        /// <summary>
        /// Browse for Base Policy - Button Click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                filesAndFoldersBasePolicyPath = selectedFile;

            }
        }


        /// <summary>
        /// Link to the page that shows scanned file details
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersViewFileDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            MainWindow.Instance.Navigate_ToPage(null, "CreateSupplementalPolicyFilesAndFoldersScanResults", null, "Create Supplemental Policy - Details");
        }


        /// <summary>
        /// File Scan Level ComboBox - Settings Card Click to simulate ComboBox click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ScanLevelComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            ScanLevelComboBox.IsDropDownOpen = !ScanLevelComboBox.IsDropDownOpen;
        }


        /// <summary>
        /// Deploy policy Toggle Button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
        {
            filesAndFoldersDeployButton = ((ToggleButton)sender).IsChecked ?? false;
        }


        /// <summary>
        /// To detect when File Scan Level ComboBox level changes
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ScanLevelComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                string selectedText = selectedItem.Content.ToString()!;

                if (!Enum.TryParse(selectedText, out filesAndFoldersScanLevel))
                {
                    throw new InvalidOperationException($"{selectedText} is not a valid Scan Level");
                }
            }
        }


        /// <summary>
        /// When the Supplemental Policy Name Textbox text changes
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            filesAndFoldersSupplementalPolicyName = ((TextBox)sender).Text;
        }


        /// <summary>
        /// Button to clear the list of selected file paths
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
        {
            filesAndFoldersFilePaths.Clear();
            FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text = null;
        }


        /// <summary>
        /// Button to clear the list of selected folder paths
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
        {
            filesAndFoldersFolderPaths.Clear();
            FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text = null;
        }


        /// <summary>
        /// Main button's event handler for files and folder Supplemental policy creation
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void CreateFilesAndFoldersSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
        {

            // Close the teaching tip if it's open when user presses the button
            // it will be opened again if necessary
            CreateSupplementalPolicyTeachingTip.IsOpen = false;


            if (filesAndFoldersFilePaths.Count == 0 && filesAndFoldersFolderPaths.Count == 0)
            {
                CreateSupplementalPolicyTeachingTip.IsOpen = true;
                CreateSupplementalPolicyTeachingTip.Title = "Select files or folders";
                CreateSupplementalPolicyTeachingTip.Subtitle = "No files or folders were selected for Supplemental policy creation";
                return;
            }

            if (filesAndFoldersBasePolicyPath is null)
            {
                CreateSupplementalPolicyTeachingTip.IsOpen = true;
                CreateSupplementalPolicyTeachingTip.Title = "Select base policy";
                CreateSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
                return;
            }

            if (string.IsNullOrWhiteSpace(filesAndFoldersSupplementalPolicyName))
            {
                CreateSupplementalPolicyTeachingTip.IsOpen = true;
                CreateSupplementalPolicyTeachingTip.Title = "Choose Supplemental Policy Name";
                CreateSupplementalPolicyTeachingTip.Subtitle = "You need to provide a name for the Supplemental policy.";
                return;
            }


            bool errorsOccurred = false;

            try
            {

                CreateCertificatesSupplementalPolicyButton.IsEnabled = false;

                FilesAndFoldersPolicyDeployToggleButton.IsEnabled = false;
                CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = false;
                FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = false;
                FilesAndFoldersBrowseForFilesButton.IsEnabled = false;
                FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = false;
                FilesAndFoldersBrowseForFoldersButton.IsEnabled = false;
                FilesAndFoldersPolicyNameTextBox.IsEnabled = false;
                FilesAndFoldersBrowseForBasePolicySettingsCard.IsEnabled = false;
                FilesAndFoldersBrowseForBasePolicyButton.IsEnabled = false;
                ScanLevelComboBoxSettingsCard.IsEnabled = false;
                ScanLevelComboBox.IsEnabled = false;
                FilesAndFoldersViewFileDetailsSettingsCard.IsEnabled = true;

                FilesAndFoldersInfoBar.IsOpen = true;
                FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Informational;
                string msg1 = $"You selected {filesAndFoldersFilePaths.Count} files and {filesAndFoldersFolderPaths.Count} folders.";
                FilesAndFoldersInfoBar.Message = msg1;
                Logger.Write(msg1);

                // Clear variables responsible for the DataGrid
                filesAndFoldersScanResultsList.Clear();
                filesAndFoldersScanResults.Clear();

                double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge

                ScalabilityRadialGauge.IsEnabled = false;

                await Task.Run(() =>
                {

                    DirectoryInfo[] selectedDirectories = [];

                    // Convert user selected folder paths that are strings to DirectoryInfo objects
                    selectedDirectories = [.. filesAndFoldersFolderPaths.Select(dir => new DirectoryInfo(dir))];

                    FileInfo[] selectedFiles = [];

                    // Convert user selected file paths that are strings to FileInfo objects
                    selectedFiles = [.. filesAndFoldersFilePaths.Select(file => new FileInfo(file))];

                    // Collect all of the AppControl compatible files from user selected directories and files
                    List<FileInfo> DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, selectedFiles, null);


                    // Make sure there are AppControl compatible files
                    if (DetectedFilesInSelectedDirectories.Count == 0)
                    {
                        _ = DispatcherQueue.TryEnqueue(() =>
                        {
                            CreateSupplementalPolicyTeachingTip.IsOpen = true;
                            CreateSupplementalPolicyTeachingTip.Title = "No compatible files detected";
                            CreateSupplementalPolicyTeachingTip.Subtitle = "No AppControl compatible files have been detected in any of the files and folder paths you selected";
                            errorsOccurred = true;
                            FilesAndFoldersInfoBar.IsOpen = false;
                            FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Informational;
                            FilesAndFoldersInfoBar.Message = null;
                        });

                        return;
                    }


                    string msg2 = $"Scanning a total of {DetectedFilesInSelectedDirectories.Count} AppControl compatible files...";
                    Logger.Write(msg2);

                    _ = DispatcherQueue.TryEnqueue(() =>
                    {
                        FilesAndFoldersInfoBar.Message = msg2;
                    });


                    // Scan all of the detected files from the user selected directories
                    HashSet<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(DetectedFilesInSelectedDirectories, (ushort)radialGaugeValue, FilesAndFoldersProgressBar, null);

                    // Add the results of the directories scans to the DataGrid
                    foreach (FileIdentity item in LocalFilesResults)
                    {
                        _ = DispatcherQueue.TryEnqueue(() =>
                        {
                            filesAndFoldersScanResults.Add(item);
                            filesAndFoldersScanResultsList.Add(item);

                        });
                    }


                    string msg3 = "Scan completed, creating the Supplemental policy";

                    Logger.Write(msg3);

                    _ = DispatcherQueue.TryEnqueue(() =>
                    {
                        FilesAndFoldersInfoBar.Message = msg3;
                    });

                    DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersSupplementalPolicy");

                    // Get the path to an empty policy file
                    string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

                    // Separate the signed and unsigned data
                    FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: filesAndFoldersScanLevel);

                    // Insert the data into the empty policy file
                    XMLOps.Initiate(DataPackage, EmptyPolicyPath);

                    string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersSupplementalPolicyName}.xml");

                    // Instantiate the user selected Base policy - To get its BasePolicyID
                    CodeIntegrityPolicy codeIntegrityPolicy = new(filesAndFoldersBasePolicyPath, null);

                    // Set the BasePolicyID of our new policy to the one from user selected policy
                    string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersSupplementalPolicyName, codeIntegrityPolicy.BasePolicyID, null);

                    // Configure policy rule options
                    CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

                    // Set policy version
                    SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

                    // Copying the policy file to the User Config directory - outside of the temporary staging area
                    File.Copy(EmptyPolicyPath, OutputPath, true);


                    // If user selected to deploy the policy
                    if (filesAndFoldersDeployButton)
                    {

                        string msg4 = "Deploying the Supplemental policy on the system";

                        Logger.Write(msg4);

                        _ = DispatcherQueue.TryEnqueue(() =>
                        {
                            FilesAndFoldersInfoBar.Message = msg4;
                        });


                        string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                        PolicyToCIPConverter.Convert(OutputPath, CIPPath);

                        CiToolHelper.UpdatePolicy(CIPPath);
                    }




                });

            }
            catch
            {
                FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Error;
                FilesAndFoldersInfoBar.Message = "An error occurred while creating the Supplemental policy";

                errorsOccurred = true;

                throw;
            }
            finally
            {
                if (!errorsOccurred)
                {
                    FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Success;
                    FilesAndFoldersInfoBar.Message = $"Successfully created a Supplemental named '{filesAndFoldersSupplementalPolicyName}'";
                }

                FilesAndFoldersInfoBar.IsClosable = true;

                FilesAndFoldersPolicyDeployToggleButton.IsEnabled = true;
                CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = true;
                FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = true;
                FilesAndFoldersBrowseForFilesButton.IsEnabled = true;
                FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = true;
                FilesAndFoldersBrowseForFoldersButton.IsEnabled = true;
                FilesAndFoldersPolicyNameTextBox.IsEnabled = true;
                FilesAndFoldersBrowseForBasePolicySettingsCard.IsEnabled = true;
                FilesAndFoldersBrowseForBasePolicyButton.IsEnabled = true;
                ScanLevelComboBoxSettingsCard.IsEnabled = true;
                ScanLevelComboBox.IsEnabled = true;


                // Clear variables and UI fields for the next round
                filesAndFoldersFilePaths.Clear();
                filesAndFoldersFolderPaths.Clear();


                // Clear the TextBoxes in the Flyouts
                FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text = null;
                FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text = null;


                CreateCertificatesSupplementalPolicyButton.IsEnabled = true;


                ScalabilityRadialGauge.IsEnabled = true;
            }
        }


        // Event handler for RadialGauge ValueChanged
        private void ScalabilityRadialGauge_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
        {
            if (sender is RadialGauge gauge)
            {
                // Update the button content with the current value of the gauge
                ScalabilityButton.Content = $"Scalability: {gauge.Value:N0}";
            }
        }

        #endregion




        #region


        // Selected Certificate File Paths
        private readonly HashSet<string> CertificatesBasedCertFilePaths = [];

        // Selected Base policy path
        private string? CertificatesBasedBasePolicyPath;

        // Selected Supplemental policy name
        private string? CertificatesBasedSupplementalPolicyName;

        private bool CertificatesBasedDeployButton;

        // Signing Scenario
        // True = User Mode
        // False = Kernel Mode
        private bool signingScenario = true;

        /// <summary>
        /// Deploy button event handler for Certificates-based Supplemental policy
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CertificatesPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
        {
            CertificatesBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
        }

        private void CertificatesBrowseForCertsButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "Certificate file|*.cer";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    _ = CertificatesBasedCertFilePaths.Add(file);
                }
            }
        }

        private void CertificatesBrowseForCertsSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "Certificate file|*.cer";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    _ = CertificatesBasedCertFilePaths.Add(file);
                }
            }
        }

        private void CertificatesPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            CertificatesBasedSupplementalPolicyName = ((TextBox)sender).Text;
        }


        private void CertificatesBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                CertificatesBasedBasePolicyPath = selectedFile;

            }
        }

        private void CertificatesBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                CertificatesBasedBasePolicyPath = selectedFile;

            }
        }



        private void UserModeRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            signingScenario = true;
        }

        private void KernelModeRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            signingScenario = false;
        }



        /// <summary>
        /// Main Button - Creates the Certificates-based Supplemental policy
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void CreateCertificatesSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
        {
            bool errorsOccurred = false;

            if (CertificatesBasedCertFilePaths.Count == 0)
            {
                CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
                CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Select certificates";
                CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to select some certificates first to create Supplemental policy";
                return;
            }

            if (CertificatesBasedBasePolicyPath is null)
            {
                CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
                CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Select base policy";
                CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
                return;
            }

            if (string.IsNullOrWhiteSpace(CertificatesBasedSupplementalPolicyName))
            {
                CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
                CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Choose Supplemental Policy Name";
                CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to provide a name for the Supplemental policy.";
                return;
            }


            try
            {

                CreateCertificatesSupplementalPolicyButton.IsEnabled = false;
                CertificatesPolicyDeployToggleButton.IsEnabled = false;
                CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = false;
                CertificatesBrowseForCertsButton.IsEnabled = false;
                CertificatesBrowseForCertsSettingsCard.IsEnabled = false;
                CertificatesPolicyNameTextBox.IsEnabled = false;
                CertificatesBrowseForBasePolicySettingsCard.IsEnabled = false;
                CertificatesBrowseForBasePolicyButton.IsEnabled = false;
                CertificatesSigningScenarioSettingsCard.IsEnabled = false;
                SigningScenariosRadioButtons.IsEnabled = false;

                CertificatesInfoBar.IsOpen = true;
                CertificatesInfoBar.Message = $"Creating the Certificates-based Supplemental policy for {CertificatesBasedCertFilePaths.Count} certificates";
                CertificatesInfoBar.Severity = InfoBarSeverity.Informational;


                await Task.Run(() =>
                {


                    DirectoryInfo stagingArea = StagingArea.NewStagingArea("CertificatesSupplementalPolicy");

                    // Get the path to an empty policy file
                    string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);


                    List<CertificateSignerCreator> certificateResults = [];


                    foreach (string certificate in CertificatesBasedCertFilePaths)
                    {
                        //  Create a certificate object from the .cer file
                        X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificate);

                        // Create rule for the certificate based on the first element in its chain
                        certificateResults.Add(new CertificateSignerCreator(
                           CertificateHelper.GetTBSCertificate(CertObject),
                            (CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false)),
                            signingScenario ? 1 : 0 // By default it's set to User-Mode in XAML/UI
                        ));

                    }


                    if (certificateResults.Count > 0)
                    {
                        // Generating signer rules
                        NewCertificateSignerRules.Create(EmptyPolicyPath, certificateResults);
                    }
                    else
                    {
                        _ = DispatcherQueue.TryEnqueue(() =>
                         {
                             CertificatesInfoBar.IsOpen = true;
                             CertificatesInfoBar.Message = $"No certificate details could be found for creating the policy";
                             CertificatesInfoBar.Severity = InfoBarSeverity.Warning;
                         });

                        errorsOccurred = true;
                        return;
                    }

                    SiPolicy.Merger.Merge(EmptyPolicyPath, [EmptyPolicyPath]);

                    string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{CertificatesBasedSupplementalPolicyName}.xml");

                    // Instantiate the user selected Base policy - To get its BasePolicyID
                    CodeIntegrityPolicy codeIntegrityPolicy = new(CertificatesBasedBasePolicyPath, null);

                    // Set the BasePolicyID of our new policy to the one from user selected policy
                    string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, CertificatesBasedSupplementalPolicyName, codeIntegrityPolicy.BasePolicyID, null);

                    // Configure policy rule options
                    CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

                    // Set policy version
                    SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

                    // Copying the policy file to the User Config directory - outside of the temporary staging area
                    File.Copy(EmptyPolicyPath, OutputPath, true);


                    // If user selected to deploy the policy
                    if (CertificatesBasedDeployButton)
                    {

                        string msg4 = "Deploying the Supplemental policy on the system";

                        Logger.Write(msg4);

                        _ = DispatcherQueue.TryEnqueue(() =>
                        {
                            CertificatesInfoBar.Message = msg4;
                        });


                        string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                        PolicyToCIPConverter.Convert(OutputPath, CIPPath);

                        CiToolHelper.UpdatePolicy(CIPPath);
                    }

                });

            }

            catch
            {

                CertificatesInfoBar.Severity = InfoBarSeverity.Error;
                CertificatesInfoBar.Message = "An error occurred while creating certificate based Supplemental policy";

                errorsOccurred = true;

                throw;
            }
            finally
            {
                if (!errorsOccurred)
                {
                    CertificatesInfoBar.Severity = InfoBarSeverity.Success;

                    CertificatesInfoBar.Message = $"Successfully created a certificate-based Supplemental policy named {CertificatesBasedSupplementalPolicyName}.";

                }



                CreateCertificatesSupplementalPolicyButton.IsEnabled = true;
                CertificatesPolicyDeployToggleButton.IsEnabled = true;
                CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = true;
                CertificatesBrowseForCertsButton.IsEnabled = true;
                CertificatesBrowseForCertsSettingsCard.IsEnabled = true;
                CertificatesPolicyNameTextBox.IsEnabled = true;
                CertificatesBrowseForBasePolicySettingsCard.IsEnabled = true;
                CertificatesBrowseForBasePolicyButton.IsEnabled = true;
                CertificatesSigningScenarioSettingsCard.IsEnabled = true;
                SigningScenariosRadioButtons.IsEnabled = true;
            }

        }



        #endregion

    }
}
