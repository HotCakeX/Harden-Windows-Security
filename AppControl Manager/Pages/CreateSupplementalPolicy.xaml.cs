using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;


public sealed partial class CreateSupplementalPolicy : Page, Sidebar.IAnimatedIconsManager
{

	// A static instance of the CreateSupplementalPolicy class which will hold the single, shared instance of the page
	private static CreateSupplementalPolicy? _instance;

	public CreateSupplementalPolicy()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		// Assign this instance to the static field
		_instance = this;
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3)
	{
		// Light up the local page's button icons
		FilesAndFoldersBasePolicyLightAnimatedIcon.Visibility = visibility;
		CertificatesBasePolicyPathLightAnimatedIcon.Visibility = visibility;
		ISGBasePolicyPathLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;
		button2.Visibility = visibility;
		button3.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;


		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Files And Folders Supplemental Policy";
			button2.Content = "Certificates Based Supplemental Policy";
			button3.Content = "ISG Supplemental Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

			// Assign a local event handler to the sidebar button
			button2.Click += LightUp2;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect2EventHandler = LightUp2;

			// Assign a local event handler to the sidebar button
			button3.Click += LightUp3;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect3EventHandler = LightUp3;
		}

	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		filesAndFoldersBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}
	private void LightUp2(object sender, RoutedEventArgs e)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (CertificatesBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
		}

		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		CertificatesBasedBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}
	private void LightUp3(object sender, RoutedEventArgs e)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (ISGBrowseForBasePolicyButton.XamlRoot is not null)
		{
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
		}

		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		ISGBasedBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}

	#endregion



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
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
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
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
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

		if (selectedDirectories is { Count: > 0 })
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

		if (selectedDirectories is { Count: > 0 })
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

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			filesAndFoldersBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}

		// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
		FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicySettingsCard);
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			filesAndFoldersBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	/// <summary>
	/// Link to the page that shows scanned file details
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersViewFileDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(CreateSupplementalPolicyFilesAndFoldersScanResults), null);
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

		// Reset the progress bar from previous runs or in case an error occurred
		FilesAndFoldersProgressBar.Value = 0;

		FilesAndFoldersInfoBar.IsClosable = false;

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
			string msg1 = $"Finding all App Control compatible files among {filesAndFoldersFilePaths.Count} files and {filesAndFoldersFolderPaths.Count} folders you selected...";
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
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

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
				FilesAndFoldersInfoBar.Message = $"Successfully created a Supplemental policy named '{filesAndFoldersSupplementalPolicyName}'";
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



	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersBasePolicyPath = null;
		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}

	#endregion




	#region Certificates scan


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

		if (selectedFiles is { Count: > 0 })
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

		if (selectedFiles is { Count: > 0 })
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

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;

			CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}

		CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicySettingsCard);
	}

	private void CertificatesBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;

			CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
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
					// Create a certificate object from the .cer file
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

				Merger.Merge(EmptyPolicyPath, [EmptyPolicyPath]);

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



	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertificatesBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		CertificatesBasedBasePolicyPath = null;
		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}



	#endregion








	#region ISG


	private string? ISGBasedBasePolicyPath;

	private bool ISGBasedDeployButton;

	// Selected Supplemental policy name
	private string? ISGBasedSupplementalPolicyName;


	/// <summary>
	/// Event handler for the main button - to create Supplemental ISG based policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateISGSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		bool errorsOccurred = false;

		if (ISGBasedBasePolicyPath is null)
		{
			CreateISGSupplementalPolicyTeachingTip.IsOpen = true;
			CreateISGSupplementalPolicyTeachingTip.Title = "Select base policy";
			CreateISGSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
			return;
		}


		try
		{

			CreateISGSupplementalPolicyButton.IsEnabled = false;
			ISGPolicyDeployToggleButton.IsEnabled = false;
			ISGPolicyNameTextBox.IsEnabled = false;
			ISGBrowseForBasePolicyButton.IsEnabled = false;


			ISGInfoBar.IsOpen = true;
			ISGInfoBar.Message = $"Creating the ISG-based Supplemental policy.";
			ISGInfoBar.Severity = InfoBarSeverity.Informational;


			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("ISGBasedSupplementalPolicy");

				// Defining the paths
				string savePathTemp = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.xml");
				string savePathFinal = Path.Combine(GlobalVars.UserConfigDir, "ISGBasedSupplementalPolicy.xml");
				string cipPath = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.cip");

				// Instantiate the user-selected base policy
				CodeIntegrityPolicy basePolicyObj = new(ISGBasedBasePolicyPath, null);

				// Instantiate the supplemental policy
				SiPolicy.SiPolicy supplementalPolicyObj = Management.Initialize(GlobalVars.ISGOnlySupplementalPolicyPath);

				// If policy name was provided by user
				if (!string.IsNullOrWhiteSpace(ISGBasedSupplementalPolicyName))
				{
					// Finding the policy name in the settings
					List<Setting> nameSettings = [.. supplementalPolicyObj.Settings.Where(x =>
					string.Equals(x.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.Key, "Information", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.ValueName, "Name", StringComparison.OrdinalIgnoreCase))];

					SettingValueType settingVal = new()
					{
						Item = ISGBasedSupplementalPolicyName
					};

					foreach (Setting setting in nameSettings)
					{
						setting.Value = settingVal;
					}
				}

				// Replace the BasePolicyID in the Supplemental policy
				supplementalPolicyObj.BasePolicyID = basePolicyObj.BasePolicyID;

				// Save the policy object to XML file in the staging Area
				Management.SavePolicyToFile(supplementalPolicyObj, savePathTemp);

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(savePathTemp, savePathFinal, true);

				// If the policy is to be deployed
				if (ISGBasedDeployButton)
				{
					// Prepare the ISG services
					ConfigureISGServices.Configure();

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(savePathTemp, cipPath);

					// Deploy the signed CIP file
					CiToolHelper.UpdatePolicy(cipPath);
				}

			});

		}
		catch (Exception ex)
		{
			errorsOccurred = true;

			ISGInfoBar.Severity = InfoBarSeverity.Error;
			ISGInfoBar.Message = $"An error occurred while creating ISG based Supplemental policy: {ex.Message}";

			Logger.Write($"An error occurred while creating ISG based Supplemental policy: {ex.Message}");

			throw;
		}
		finally
		{

			if (!errorsOccurred)
			{
				ISGInfoBar.Severity = InfoBarSeverity.Success;

				ISGInfoBar.Message = $"Successfully created an ISG-based Supplemental policy.";
			}

			CreateISGSupplementalPolicyButton.IsEnabled = true;
			ISGPolicyDeployToggleButton.IsEnabled = true;
			ISGPolicyNameTextBox.IsEnabled = true;
			ISGBrowseForBasePolicyButton.IsEnabled = true;

		}
	}


	private void ISGPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		ISGBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}


	private void ISGPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		ISGBasedSupplementalPolicyName = ((TextBox)sender).Text;
	}



	private void ISGBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;

			ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}

		ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicySettingsCard);
	}


	private void ISGBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;

			ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	private void ISGBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		ISGBasedBasePolicyPath = null;
		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	#endregion





	#region Strict Kernel-Mode Supplemental Policy


	private string? StrictKernelModeBasePolicyPath;


	// Used to store the scan results and as the source for the results DataGrids
	internal ObservableCollection<FileIdentity> ScanResults = [];
	internal List<FileIdentity> ScanResultsList = [];



	private void StrictKernelModeScanButton_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePerformScans(false);
	}

	private void DetectedKernelModeFilesDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(StrictKernelPolicyScanResults), null);
	}






	/// <summary>
	/// Browse for Base Policy - Settings Card Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			StrictKernelModeBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}

		// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
		StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicySettingsCard);
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			StrictKernelModeBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}




	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModeBasePolicyPath = null;
		StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}




	private void StrictKernelModeScanSinceLastRebootButton_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePerformScans(true);
	}




	private async void StrictKernelModePerformScans(bool OnlyAfterReboot)
	{
		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = "Scanning the system for events";
			StrictKernelModeSection.IsExpanded = true;

			// Clear variables responsible for the DataGrid
			ScanResults.Clear();
			ScanResultsList.Clear();


			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

			// Filter the logs
			// Only DLL and SYS files must be included
			await Task.Run(() =>
			{
				if (OnlyAfterReboot)
				{
					DateTime lastRebootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount64);

					// Signed kernel-mode files that were run after last reboot
					Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= lastRebootTime && fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
				else
				{
					// Signed kernel-mode files
					Output = [.. Output.Where(fileIdentity => fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
			});



			// If any logs were generated since audit mode policy was deployed
			if (Output.Count > 0)
			{
				StrictKernelModeInfoBar.Message = $"{Output.Count} log(s) were generated during the Audit phase";

				// Add the event logs to the DataGrid
				foreach (FileIdentity item in Output)
				{
					ScanResults.Add(item);
					ScanResultsList.Add(item);
				}

				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = true;
			}
			else
			{
				StrictKernelModeInfoBar.Message = "No logs were generated during the Audit phase";
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = false;
				ErrorsOccurred = true;
				return;
			}


		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = $"An error occurred while scanning the system for events: {ex.Message}";
		}
		finally
		{
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully scanned the system for events";
			}

			StrictKernelModeInfoBar.IsClosable = true;

		}
	}



	/// <summary>
	/// Event handler for the create button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void StrictKernelModeCreateButton_Click(object sender, RoutedEventArgs e)
	{
		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		StrictKernelModeCreateButtonTeachingTip.IsOpen = false;

		if (ScanResults.Count is 0)
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No item exists in the detected Kernel-mode files data grid";
			return;
		}

		if (string.IsNullOrWhiteSpace(StrictKernelModePolicyNameTextBox.Text))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No policy name was selected for the supplemental policy";
			return;
		}

		if (string.IsNullOrWhiteSpace(StrictKernelModeBasePolicyPath))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No Base policy file was selected for the supplemental policy";
			return;
		}

		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeCreateButton.IsEnabled = false;
			StrictKernelModeDeployToggleButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = false;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = false;
			StrictKernelModeBrowseForBasePolicyButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = $"Creating Strict Kernel-mode supplemental policy for {ScanResults.Count} files";
			StrictKernelModeSection.IsExpanded = true;


			bool shouldDeploy = StrictKernelModeDeployToggleButton.IsChecked ?? false;

			string policyNameChosenByUser = string.Empty;

			// Enqueue the work to the UI thread
			await DispatcherQueue.EnqueueAsync(() =>
			{
				policyNameChosenByUser = StrictKernelModePolicyNameTextBox.Text;
			});

			await Task.Run(() =>
			{


				DirectoryInfo stagingArea = StagingArea.NewStagingArea("StrictKernelModeSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. ScanResults], level: ScanLevels.FilePublisher);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyNameChosenByUser}.xml");

				// Instantiate the user selected Base policy - To get its BasePolicyID
				CodeIntegrityPolicy codeIntegrityPolicy = new(StrictKernelModeBasePolicyPath, null);

				// Set the BasePolicyID of our new policy to the one from user selected policy
				string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyNameChosenByUser, codeIntegrityPolicy.BasePolicyID, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				RemoveUserModeSS.Remove(EmptyPolicyPath);

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);


				// If user selected to deploy the policy
				if (shouldDeploy)
				{

					string msg4 = "Deploying the Supplemental policy on the system";

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StrictKernelModeInfoBar.Message = msg4;
					});


					string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

					PolicyToCIPConverter.Convert(OutputPath, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}


			});

		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}

		finally
		{

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully created strict Kernel-mode supplemental policy";
			}


			StrictKernelModeCreateButton.IsEnabled = true;
			StrictKernelModeDeployToggleButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			StrictKernelModeBrowseForBasePolicyButton.IsEnabled = true;
			StrictKernelModeInfoBar.IsClosable = true;

		}

	}




	/// <summary>
	/// Event handler for the button that auto detects system drivers
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeAutoDetectAllDriversButton_Click(object sender, RoutedEventArgs e)
	{
		DriverAutoDetector();
	}

	private async void DriverAutoDetector()
	{
		bool ErrorsOccurred = false;

		try
		{

			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = false;
			StrictKernelModeCreateButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = "Scanning the system for drivers";
			StrictKernelModeSection.IsExpanded = true;

			List<FileInfo> kernelModeDriversList = [];

			ScanResults.Clear();
			ScanResultsList.Clear();

			await Task.Run(() =>
			{

				// Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added

				// Get the system drive
				string systemDrive = Environment.GetEnvironmentVariable("SystemDrive")!;

				// Define the directory path
				string directoryPath = Path.Combine(systemDrive, "Windows", "Boot", "Resources");

				// Iterate through each directory in the specified path
				foreach (string directory in Directory.GetDirectories(directoryPath))
				{
					// Add the desired file path to the list
					kernelModeDriversList.Add(new FileInfo(Path.Combine(directory, "bootres.dll.mui")));
				}

				DirectoryInfo sys32Dir = new(Path.Combine(systemDrive, "Windows", "System32"));

				List<FileInfo> filesOutput = FileUtility.GetFilesFast([sys32Dir], null, [".dll", ".sys"]);

				foreach (FileInfo file in filesOutput)
				{
					kernelModeDriversList.Add(file);
				}

			});



			if (kernelModeDriversList.Count > 0)
			{

				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = true;
			}
			else
			{
				StrictKernelModeInfoBar.Message = "No kernel-mode drivers could be detected";
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = false;
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.Message = $"Scanning {kernelModeDriversList.Count} files";

			await Task.Run(() =>
			{

				// Scan all of the detected files from the user selected directories
				HashSet<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(kernelModeDriversList, 2, null, null);

				// Add the results to the DataGrid
				// Only signed kernel-mode files
				foreach (FileIdentity item in LocalFilesResults.Where(fileIdentity => fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned))
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						ScanResults.Add(item);
						ScanResultsList.Add(item);

					});
				}

			});


		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}
		finally
		{

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully scanned the system for drivers";
			}

			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeCreateButton.IsEnabled = true;

			StrictKernelModeInfoBar.IsClosable = true;
		}
	}




	private void StrictKernelModeAutoDetectAllDriversSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		DriverAutoDetector();
	}



	#endregion


}
