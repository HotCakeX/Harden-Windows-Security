using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Logging;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class CreateDenyPolicy : Page
{

	// A static instance of the CreateDenyPolicy class which will hold the single, shared instance of the page
	private static CreateDenyPolicy? _instance;

	public CreateDenyPolicy()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Assign this instance to the static field
		_instance = this;
	}

	// Public property to access the singleton instance from other classes
	public static CreateDenyPolicy Instance => _instance ?? throw new InvalidOperationException("CreateDenyPolicy is not initialized.");



	#region Files and Folders scan

	// Selected File Paths
	private readonly HashSet<string> filesAndFoldersFilePaths = [];

	// Selected Folder Paths
	private readonly HashSet<string> filesAndFoldersFolderPaths = [];

	// Selected Deny policy name
	private string? filesAndFoldersDenyPolicyName;

	// The user selected scan level
	private ScanLevels filesAndFoldersScanLevel = ScanLevels.FilePublisher;

	private bool filesAndFoldersDeployButton;

	// Used to store the scan results and as the source for the results DataGrids
	internal ObservableCollection<FileIdentity> filesAndFoldersScanResults = [];
	internal List<FileIdentity> filesAndFoldersScanResultsList = [];





	/// <summary>
	/// Main button's event handler for files and folder Deny policy creation
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateFilesAndFoldersDenyPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreateDenyPolicyTeachingTip.IsOpen = false;

		// Reset the progress bar from previous runs or in case an error occurred
		FilesAndFoldersProgressBar.Value = 0;

		FilesAndFoldersInfoBar.IsClosable = false;

		if (filesAndFoldersFilePaths.Count == 0 && filesAndFoldersFolderPaths.Count == 0)
		{
			CreateDenyPolicyTeachingTip.IsOpen = true;
			CreateDenyPolicyTeachingTip.Title = "Select files or folders";
			CreateDenyPolicyTeachingTip.Subtitle = "No files or folders were selected for Deny policy creation";
			return;
		}



		if (string.IsNullOrWhiteSpace(filesAndFoldersDenyPolicyName))
		{
			CreateDenyPolicyTeachingTip.IsOpen = true;
			CreateDenyPolicyTeachingTip.Title = "Choose Deny Policy Name";
			CreateDenyPolicyTeachingTip.Subtitle = "You need to provide a name for the Deny policy.";
			return;
		}


		bool errorsOccurred = false;

		try
		{

			FilesAndFoldersPolicyDeployToggleButton.IsEnabled = false;
			CreateFilesAndFoldersDenyPolicyButton.IsEnabled = false;
			FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = false;
			FilesAndFoldersBrowseForFilesButton.IsEnabled = false;
			FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = false;
			FilesAndFoldersBrowseForFoldersButton.IsEnabled = false;
			FilesAndFoldersPolicyNameTextBox.IsEnabled = false;
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
						CreateDenyPolicyTeachingTip.IsOpen = true;
						CreateDenyPolicyTeachingTip.Title = "No compatible files detected";
						CreateDenyPolicyTeachingTip.Subtitle = "No AppControl compatible files have been detected in any of the files and folder paths you selected";
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


				string msg3 = "Scan completed, creating the Deny policy";

				Logger.Write(msg3);

				_ = DispatcherQueue.TryEnqueue(() =>
				{
					FilesAndFoldersInfoBar.Message = msg3;
				});

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: filesAndFoldersScanLevel);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersDenyPolicyName}.xml");

				// Set policy name and reset the policy ID
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersDenyPolicyName, null, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);


				// If user selected to deploy the policy
				if (filesAndFoldersDeployButton)
				{

					string msg4 = "Deploying the Deny policy on the system";

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.Message = msg4;
					});


					string CIPPath = Path.Combine(stagingArea.FullName, $"{filesAndFoldersDenyPolicyName}.cip");

					PolicyToCIPConverter.Convert(OutputPath, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}



			});

		}
		catch
		{
			FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Error;
			FilesAndFoldersInfoBar.Message = "An error occurred while creating the Deny policy";

			errorsOccurred = true;

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Success;
				FilesAndFoldersInfoBar.Message = $"Successfully created a Deny policy named '{filesAndFoldersDenyPolicyName}'";
			}

			FilesAndFoldersInfoBar.IsClosable = true;

			FilesAndFoldersPolicyDeployToggleButton.IsEnabled = true;
			CreateFilesAndFoldersDenyPolicyButton.IsEnabled = true;
			FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = true;
			FilesAndFoldersBrowseForFilesButton.IsEnabled = true;
			FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = true;
			FilesAndFoldersBrowseForFoldersButton.IsEnabled = true;
			FilesAndFoldersPolicyNameTextBox.IsEnabled = true;
			ScanLevelComboBoxSettingsCard.IsEnabled = true;
			ScanLevelComboBox.IsEnabled = true;

			ScalabilityRadialGauge.IsEnabled = true;
		}
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
	/// When the Deny Policy Name Textbox text changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		filesAndFoldersDenyPolicyName = ((TextBox)sender).Text;
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

	private void FilesAndFoldersViewFileDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(CreateDenyPolicyFilesAndFoldersScanResults), null);
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
	/// File Scan Level ComboBox - Settings Card Click to simulate ComboBox click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ScanLevelComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		ScanLevelComboBox.IsDropDownOpen = !ScanLevelComboBox.IsDropDownOpen;
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
	/// Button to clear the list of selected file paths
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersFilePaths.Clear();
		FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text = null;
	}


	#endregion



}
