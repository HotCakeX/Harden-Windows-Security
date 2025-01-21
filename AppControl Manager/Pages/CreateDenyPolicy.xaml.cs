using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

namespace AppControlManager.Pages;

public sealed partial class CreateDenyPolicy : Page
{

	// A static instance of the CreateDenyPolicy class which will hold the single, shared instance of the page
	private static CreateDenyPolicy? _instance;

	public CreateDenyPolicy()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

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

	private bool usingWildCardFilePathRules;

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

				HashSet<FileIdentity> LocalFilesResults = [];

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (!usingWildCardFilePathRules)
				{


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
					LocalFilesResults = LocalFilesScan.Scan(DetectedFilesInSelectedDirectories, (ushort)radialGaugeValue, FilesAndFoldersProgressBar, null);

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


				}

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: filesAndFoldersScanLevel, folderPaths: filesAndFoldersFolderPaths);

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

			// Since the texts in the ComboBox have spaces in them for user friendliness, we remove the spaces here before parsing them as enum
			if (!Enum.TryParse(selectedText.Replace(" ", ""), out filesAndFoldersScanLevel))
			{
				throw new InvalidOperationException($"{selectedText} is not a valid Scan Level");
			}



			// For Wildcard file path rules, only folder paths should be used
			if (filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath)
			{
				FilesAndFoldersBrowseForFilesButton.IsEnabled = false;
				FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = false;

				usingWildCardFilePathRules = true;
			}
			else
			{
				FilesAndFoldersBrowseForFilesButton.IsEnabled = true;
				FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = true;

				usingWildCardFilePathRules = false;
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



	#region Package Family Names

	// Package Manager object used by the PFN section
	private readonly PackageManager packageManager = new();

	/// <summary>
	/// Gets the list of all installed Packaged Apps
	/// </summary>
	/// <returns></returns>
	internal async Task<List<PackagedAppView>> GetAppsList()
	{
		return await Task.Run(() =>
		{
			// The list to return as output
			List<PackagedAppView> apps = [];

			// Get all of the packages on the system
			IEnumerable<Package> allApps = packageManager.FindPackages();

			// Loop over each package
			foreach (Package item in allApps)
			{
				// Create a new instance of the class that displays each app in the ListView
				apps.Add(new PackagedAppView(
					displayName: item.DisplayName,
					version: $"Version: {item.Id.Version.Major}.{item.Id.Version.Minor}.{item.Id.Version.Build}.{item.Id.Version.Revision}",
					packageFamilyName: $"PFN: {item.Id.FamilyName}",
					logo: item.Logo.ToString(),
					packageFamilyNameActual: item.Id.FamilyName
					));
			}

			return apps;
		});

	}



	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PFNRefreshAppsListButton_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PFNRefreshAppsListButton.IsEnabled = false;

			PackagedAppsCollectionViewSource.Source = await GetContactsGroupedAsync();
		}
		finally
		{
			PFNRefreshAppsListButton.IsEnabled = true;
		}
	}


	/// <summary>
	/// Event handler for the touch-initiated refresh action
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private async void PFNRefreshContainer_RefreshRequested(RefreshContainer sender, RefreshRequestedEventArgs args)
	{
		try
		{
			PFNRefreshAppsListButton.IsEnabled = false;

			PackagedAppsCollectionViewSource.Source = await GetContactsGroupedAsync();
		}
		finally
		{
			PFNRefreshAppsListButton.IsEnabled = true;
		}
	}


	// Since we have a ScrollView around the page, it captures the mouse Scroll Wheel events.
	// We have to disable its scrolling ability while pointer is inside of the ListView.
	// Scrolling via touch or dragging the ListView's scrollbar via mouse doesn't require this and they work either way.
	private void PFNPackagedAppsListView_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType is PointerDeviceType.Mouse)
		{
			// Disable vertical scrolling for the outer ScrollView only for mouse input
			MainScrollView.VerticalScrollMode = ScrollingScrollMode.Disabled;
		}
	}

	private void PFNPackagedAppsListView_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		// Re-enable vertical scrolling for the outer ScrollView
		MainScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;

	}

	private void MainScrollView_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType is not PointerDeviceType.Mouse)
		{
			// Always enable vertical scrolling for input that's not mouse
			MainScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;
		}
	}






	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	private async Task<ObservableCollection<GroupInfoListForPackagedAppView>> GetContactsGroupedAsync()
	{
		// Grab Apps objects from pre-existing list (list is returned from method GetAppsList())
		IEnumerable<GroupInfoListForPackagedAppView> query = from item in await GetAppsList()

																 // Ensure DisplayName is not null before grouping
																 // This also prevents apps without a DisplayName to exist in the returned apps list
															 where !string.IsNullOrWhiteSpace(item.DisplayName)

															 // Group the items returned from the query, sort and select the ones you want to keep
															 group item by item.DisplayName[..1].ToUpper() into g
															 orderby g.Key

															 // GroupInfoListForPackagedAppView is a simple custom class that has an IEnumerable type attribute, and
															 // a key attribute. The IGrouping-typed variable g now holds the App objects,
															 // and these objects will be used to create a new GroupInfoListForPackagedAppView object.
															 select new GroupInfoListForPackagedAppView(g) { Key = g.Key };

		return [.. query];
	}




	/// <summary>
	/// Event handler to select all apps in the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNSelectAllAppsListButton_Click(object sender, RoutedEventArgs e)
	{
		// Ensure the ListView has items
		if (PFNPackagedAppsListView.ItemsSource is IEnumerable<object> items)
		{
			PFNPackagedAppsListView.SelectedItems.Clear(); // Clear any existing selection

			foreach (object item in items)
			{
				PFNPackagedAppsListView.SelectedItems.Add(item); // Add each item to SelectedItems
			}
		}
	}

	/// <summary>
	/// Event handler to remove all selections of apps in the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNRemoveSelectionAppsListButton_Click(object sender, RoutedEventArgs e)
	{
		PFNPackagedAppsListView.SelectedItems.Clear(); // Clear all selected items
	}





	/// <summary>
	/// Event handler to display the selected apps count on the UI TextBlock
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNPackagedAppsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		int selectedCount = PFNPackagedAppsListView.SelectedItems.Count;
		PFNSelectedItemsCount.Text = $"Selected Apps: {selectedCount}";
	}



	// Used to store the original Apps collection so when we filter the results and then remove the filters,
	// We can still have access to the original collection of apps
	private ObservableCollection<GroupInfoListForPackagedAppView>? _originalContacts;


	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNAppFilteringTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		// Store the original collection if it hasn't been saved yet
		_originalContacts ??= (ObservableCollection<GroupInfoListForPackagedAppView>)PackagedAppsCollectionViewSource.Source;

		// Get the text from text box
		string filterText = PFNAppFilteringTextBox.Text;

		if (string.IsNullOrWhiteSpace(filterText))
		{
			// If the filter is cleared, restore the original collection
			PackagedAppsCollectionViewSource.Source = _originalContacts;
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = [.. _originalContacts
			.Select(group => new GroupInfoListForPackagedAppView(group.Where(app =>
				app.DisplayName.Contains(filterText, StringComparison.OrdinalIgnoreCase)))
			{
				Key = group.Key // Preserve the group key
			})
			.Where(group => group.Any())];

		// Update the ListView source with the filtered data
		PackagedAppsCollectionViewSource.Source = new ObservableCollection<GroupInfoListForPackagedAppView>(filtered);
	}



	private bool packagesLoadedOnExpand;

	/// <summary>
	/// Event handler to happen only once when the section is expanded and apps list is loaded
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PFNSettingsCard_Expanded(object sender, EventArgs e)
	{
		if (!packagesLoadedOnExpand)
		{
			try
			{
				PFNRefreshAppsListButton.IsEnabled = false;

				PackagedAppsCollectionViewSource.Source = await GetContactsGroupedAsync();

				packagesLoadedOnExpand = true;
			}
			finally
			{
				PFNRefreshAppsListButton.IsEnabled = true;
			}
		}
	}




	/// <summary>
	/// Main button's event handler - Create Deny policy based on PFNs
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreatePFNDenyPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? PFNBasedDenyPolicyName = PFNPolicyNameTextBox.Text;

		bool shouldDeploy = PFNPolicyDeployToggleButton.IsChecked ?? false;

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreatePFNDenyPolicyTeachingTip.IsOpen = false;

		if (PFNPackagedAppsListView.SelectedItems.Count is 0)
		{
			CreatePFNDenyPolicyTeachingTip.IsOpen = true;
			CreatePFNDenyPolicyTeachingTip.Title = "PFN based Deny policy";
			CreatePFNDenyPolicyTeachingTip.Subtitle = "No app was selected to create a deny policy for";
			return;
		}

		if (string.IsNullOrWhiteSpace(PFNBasedDenyPolicyName))
		{
			CreatePFNDenyPolicyTeachingTip.IsOpen = true;
			CreatePFNDenyPolicyTeachingTip.Title = "PFN based Deny policy";
			CreatePFNDenyPolicyTeachingTip.Subtitle = "No policy name was selected for the deny policy";
			return;
		}



		bool ErrorsOccurred = false;

		try
		{

			CreatePFNDenyPolicyButton.IsEnabled = false;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = false;
			PFNPolicyNameTextBox.IsEnabled = false;

			PFNInfoBar.IsClosable = false;
			PFNInfoBar.IsOpen = true;
			PFNInfoBar.Severity = InfoBarSeverity.Informational;
			PFNInfoBar.Message = "Creating the deny policy based on Package Family Names";
			PFNSettingsCard.IsExpanded = true;


			// A list to store the selected PackagedAppView items
			List<string> selectedAppsPFNs = [];




			// Loop through the selected items
			foreach (var selectedItem in PFNPackagedAppsListView.SelectedItems)
			{
				if (selectedItem is PackagedAppView appView)
				{
					// Add the selected item's PFN to the list
					selectedAppsPFNs.Add(appView.PackageFamilyNameActual);
				}
			}





			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PFNDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(level: ScanLevels.PFN, packageFamilyNames: selectedAppsPFNs);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedDenyPolicyName}.xml");

				// Set policy name and reset the policy ID
				string denyPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, PFNBasedDenyPolicyName, null, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);


				// If user selected to deploy the policy
				if (shouldDeploy)
				{

					string msg4 = "Deploying the Deny policy on the system";

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						PFNInfoBar.Message = msg4;
					});


					string CIPPath = Path.Combine(stagingArea.FullName, $"{denyPolicyID}.cip");

					PolicyToCIPConverter.Convert(OutputPath, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}



			});


		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			PFNInfoBar.Severity = InfoBarSeverity.Error;
			PFNInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}
		finally
		{

			if (!ErrorsOccurred)
			{
				PFNInfoBar.Severity = InfoBarSeverity.Success;
				PFNInfoBar.Message = "Successfully created the Deny policy";
			}

			CreatePFNDenyPolicyButton.IsEnabled = true;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = true;
			PFNPolicyNameTextBox.IsEnabled = true;

			PFNInfoBar.IsClosable = true;
		}


	}





	#endregion


}
