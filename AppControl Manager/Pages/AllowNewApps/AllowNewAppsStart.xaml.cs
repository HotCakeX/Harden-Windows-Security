using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;


namespace AppControlManager.Pages;

public sealed partial class AllowNewAppsStart : Page, Sidebar.IAnimatedIconsManager
{

	// The user selected XML base policy path
	internal string? selectedXMLFilePath;

	// The user selected Supplemental policy name
	private static string? selectedSupplementalPolicyName;

	// The user selected directories to scan
	private static readonly HashSet<string> selectedDirectoriesToScan = [];

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

	// Custom HashSet to store the output of both local files and event logs scans
	// If the same file is detected in event logs And local file scans, the one with IsECCSigned property set to true will be kept
	// So that the respective methods will make Hash based rule for that file since AppControl doesn't support ECC Signed files yet
	private static readonly FileIdentityECCBasedHashSet fileIdentities = new();

	#region

	// To store the FileIdentities displayed on the Local Files DataGrid
	internal ObservableCollection<FileIdentity> LocalFilesFileIdentities { get; set; }

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal List<FileIdentity> LocalFilesAllFileIdentities;


	// To store the FileIdentities displayed on the Event Logs DataGrid
	internal ObservableCollection<FileIdentity> EventLogsFileIdentities { get; set; }

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal List<FileIdentity> EventLogsAllFileIdentities;

	#endregion


	// A static instance of the AllowNewAppsStart class which will hold the single, shared instance of the page
	private static AllowNewAppsStart? _instance;

	// The ThemeShadow defined in Grid XAML
	private readonly ThemeShadow sharedShadow;

	// Will determine whether the user selected XML policy file is signed or unsigned
	private bool _IsSignedPolicy;

	// The base policy XML objectified
	private SiPolicy.SiPolicy? _BasePolicyObject;

	// To hold the necessary details for policy signing if the selected base policy is signed
	// They will be retrieved from the content dialog
	private string? _CertCN;
	private string? _CertPath;
	private string? _SignToolPath;

	public AllowNewAppsStart()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Assign this instance to the static field
		_instance = this;

		// Get the ThemeShadow defined in the XAML
		sharedShadow = RootGrid.Resources["SharedShadow"] as ThemeShadow ?? throw new InvalidOperationException("sharedShadow could not be found");

		// Initially disable Steps 2 and 3
		SetBorderStyles(Step1Border);
		DisableStep2();
		DisableStep3();

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


	#region Augmentation Interface


	// Exposing the AnimatedIcon via class instance since this is an internal page managed by AllowNewApps page's own NavigationView
	internal AnimatedIcon BrowseForXMLPolicyButtonLightAnimatedIconPub => BrowseForXMLPolicyButtonLightAnimatedIcon;

	// Exposing more elements to the main page of AllowNewApps since this is a sub-page managed by a 2nd NavigationView
	internal Flyout BrowseForXMLPolicyButton_FlyOutPub => BrowseForXMLPolicyButton_FlyOut;
	internal Button BrowseForXMLPolicyButtonPub => BrowseForXMLPolicyButton;
	internal TextBox BrowseForXMLPolicyButton_SelectedBasePolicyTextBoxPub => BrowseForXMLPolicyButton_SelectedBasePolicyTextBox;



	private string? unsignedBasePolicyPathFromSidebar;


	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3, Button button4, Button button5)
	{
		// Light up the local page's button icons
		BrowseForXMLPolicyButtonLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;


		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Allow New Apps Base Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

		}

	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyButton_FlyOut.ShowAt(BrowseForXMLPolicyButton);
		BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		selectedXMLFilePath = unsignedBasePolicyPathFromSidebar;
	}



	#endregion


	#region Steps management

	private void DisableStep1()
	{
		BrowseForXMLPolicyButton.IsEnabled = false;
		GoToStep2Button.IsEnabled = false;
		SupplementalPolicyNameTextBox.IsEnabled = false;
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
			if (string.IsNullOrWhiteSpace(selectedXMLFilePath))
			{
				throw new InvalidOperationException("You need to select a XML policy file path");
			}

			// Ensure the selected XML file path exists on the disk
			if (!File.Exists(selectedXMLFilePath))
			{
				throw new InvalidOperationException($"The selected XML file path doesn't exist {selectedXMLFilePath}");
			}

			await Task.Run(() =>
			{
				// Instantiate the selected policy file
				_BasePolicyObject = Management.Initialize(selectedXMLFilePath);

				if (_BasePolicyObject.PolicyType is not PolicyType.BasePolicy)
				{
					throw new InvalidOperationException($"The selected XML policy file must be Base policy type, but its type is '{_BasePolicyObject.PolicyType}'");
				}

				// Get all deployed base policies
				List<CiPolicyInfo> allDeployedBasePolicies = CiToolHelper.GetPolicies(false, true, false);

				// Get all the deployed base policyIDs
				List<string?> CurrentlyDeployedBasePolicyIDs = [.. allDeployedBasePolicies.Select(p => p.BasePolicyID)];

				// Trim the curly braces from the policyID
				string trimmedPolicyID = _BasePolicyObject.PolicyID.TrimStart('{').TrimEnd('}');

				// Make sure the selected policy is deployed on the system
				if (!CurrentlyDeployedBasePolicyIDs.Any(id => string.Equals(id, trimmedPolicyID, StringComparison.OrdinalIgnoreCase)))
				{
					throw new InvalidOperationException($"The selected policy file {selectedXMLFilePath} is not deployed on the system.");
				}


				// If the policy doesn't have any rule options or it doesn't have the EnabledUnsignedSystemIntegrityPolicy rule option then it is signed
				_IsSignedPolicy = (_BasePolicyObject.Rules is null || !_BasePolicyObject.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy));
			});


			if (_IsSignedPolicy)
			{

				Logger.Write("Signed policy detected");

				#region Signing Details acquisition

				// Instantiate the Content Dialog
				SigningDetailsDialog customDialog = new(_BasePolicyObject);

				// Show the dialog and await its result
				ContentDialogResult result = await customDialog.ShowAsync();

				// Ensure primary button was selected
				if (result is ContentDialogResult.Primary)
				{
					_SignToolPath = customDialog.SignToolPath!;
					_CertPath = customDialog.CertificatePath!;
					_CertCN = customDialog.CertificateCommonName!;
				}
				else
				{
					GoToStep2Button.IsEnabled = true;

					return;
				}

				#endregion
			}


			// Execute the main tasks of step 1
			await Task.Run(() =>
			{

				// Create the required directory and file paths in step 1
				stagingArea = StagingArea.NewStagingArea("AllowNewApps");
				tempBasePolicyPath = Path.Combine(stagingArea.FullName, "BasePolicy.XML");
				AuditModeCIP = Path.Combine(stagingArea.FullName, "BaseAudit.cip");

				// Make sure it stays unique because it's being put outside of the StagingArea and we don't want any other command to remove or overwrite it
				EnforcedModeCIP = Path.Combine(GlobalVars.UserConfigDir, $"BaseEnforced-{GUIDGenerator.GenerateUniqueGUID()}.cip");

				_ = DispatcherQueue.TryEnqueue(() =>
				{
					Step1InfoBar.IsOpen = true;
					Step1InfoBar.Message = "Deploying the selected policy in Audit mode, please wait";
				});

				// Creating a copy of the original policy in the Staging Area so that the original one will be unaffected
				File.Copy(selectedXMLFilePath, tempBasePolicyPath, true);

				// If the policy is Unsigned
				if (!_IsSignedPolicy)
				{
					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode]);
					PolicyToCIPConverter.Convert(tempBasePolicyPath, AuditModeCIP);

					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode]);
					PolicyToCIPConverter.Convert(tempBasePolicyPath, EnforcedModeCIP);
				}

				// If the policy is Signed
				else
				{

					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode], rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy]);

					string CIPp7SignedFilePathAudit = Path.Combine(stagingArea.FullName, "BaseAudit.cip.p7");

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(tempBasePolicyPath, AuditModeCIP);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(AuditModeCIP), new FileInfo(_SignToolPath!), _CertCN!);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePathAudit, AuditModeCIP, true);



					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledAuditMode, CiRuleOptions.PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy]);

					string CIPp7SignedFilePathEnforced = Path.Combine(stagingArea.FullName, "BaseAuditTemp.cip.p7");

					string tempEnforcedModeCIPPath = Path.Combine(stagingArea.FullName, "BaseAuditTemp.cip");

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(tempBasePolicyPath, tempEnforcedModeCIPPath);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(tempEnforcedModeCIPPath), new FileInfo(_SignToolPath!), _CertCN!);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePathEnforced, EnforcedModeCIP, true);

				}


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

			// Capture the current time so that the audit logs that will be displayed will be newer than that
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

				// Clear the variables if errors occurred in step 1
				_BasePolicyObject = null;
				_CertCN = null;
				_CertPath = null;
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

			// While the base policy is being deployed is audit mode, set the progress ring as indeterminate
			Step2ProgressRing.IsIndeterminate = true;

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

						// Set the progress ring to no longer be indeterminate since file scan will take control of its value
						Step2ProgressRing.IsIndeterminate = false;
					});


					DirectoryInfo[] selectedDirectories = [];

					// Convert user selected folder paths that are strings to DirectoryInfo objects
					selectedDirectories = [.. selectedDirectoriesToScan.Select(dir => new DirectoryInfo(dir))];

					// Get all of the AppControl compatible files from user selected directories
					List<FileInfo> DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, null, null);

					// If any App Control compatible files were found in the user selected directories
					if (DetectedFilesInSelectedDirectories.Count > 0)
					{

						_ = DispatcherQueue.TryEnqueue(() =>
						{
							Step2InfoBar.Message = $"Scanning {DetectedFilesInSelectedDirectories.Count} files found in the selected directories";

							// Set the progress ring to no longer be indeterminate since file scan will take control of its value
							Step2ProgressRing.IsIndeterminate = false;
						});

						// Scan all of the detected files from the user selected directories
						HashSet<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(DetectedFilesInSelectedDirectories, 2, null, Step2ProgressRing);

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
				}
			});

			// Update the total logs on that page once we add data to it from here
			// If the page is not loaded yet then this won't run since it's nullable. Upon switching to that page however the OnNavigateTo event will update the count.
			// If the page is already loaded and user is sitting on it, that means instance is initialized so we can update it in real time from here.
			AllowNewAppsLocalFilesDataGrid.Instance?.UpdateTotalLogs();

			// Update the InfoBadge for the top menu
			AllowNewApps.Instance.UpdateLocalFilesInfoBadge(LocalFilesFileIdentities.Count, 1);


			Step2InfoBar.Message = "Scanning the event logs";

			// Log scanning doesn't produce determinate real time progress so setting it as indeterminate
			Step2ProgressRing.IsIndeterminate = true;

			// Check for available logs

			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

			// Filter the logs and keep only ones generated after audit mode policy was deployed
			await Task.Run(() =>
			{
				Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= LogsScanStartTime)];
			});


			Step2InfoBar.Message = $"{Output.Count} log(s) were generated during the Audit phase";

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

			// Update the InfoBadge for the top menu
			AllowNewApps.Instance.UpdateEventLogsInfoBadge(EventLogsFileIdentities.Count, 1);


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

				// When an error occurs before the disable methods run, we need to clear them manually here
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

			ResetStepsButton.IsEnabled = false;

			ResetProgressRing.IsActive = true;

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
			fileIdentities.FileIdentitiesInternal.Clear();
			selectedDirectoriesToScan.Clear();
			deployPolicy = true;
			selectedSupplementalPolicyName = null;
			LogsScanStartTime = null;
			tempBasePolicyPath = null;
			_BasePolicyObject = null;
			_CertCN = null;
			_CertPath = null;
			_SignToolPath = null;
			_IsSignedPolicy = false;

			LogSizeNumberBox.Value = EventLogUtility.GetCurrentLogSize();

			// Disable the data grids access
			AllowNewApps.Instance.DisableAllowNewAppsNavigationItem("LocalFiles");
			AllowNewApps.Instance.DisableAllowNewAppsNavigationItem("EventLogs");


			// Update the InfoBadges for the top menu
			AllowNewApps.Instance.UpdateEventLogsInfoBadge(0, 0);
			AllowNewApps.Instance.UpdateLocalFilesInfoBadge(0, 0);

			// Reset the UI inputs back to their default states
			DeployToggleButton.IsChecked = true;
			SelectedDirectoriesTextBox.Text = null;
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

					// Delete the enforced mode CIP file from the user config directory after deploying it
					File.Delete(EnforcedModeCIP);
				}

				// Remove the snap back guarantee task and .bat file if it exists
				SnapBackGuarantee.Remove();
			});


		}
		finally
		{
			// Enable the step1 for new operation
			EnableStep1();
			ResetProgressRing.IsActive = false;
			ResetStepsButton.IsEnabled = true;
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

		List<string>? selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders is { Count: > 0 })
		{
			// Add each folder to the HashSet of the selected directories
			foreach (string folder in selectedFolders)
			{
				// If the add was successful then display it on the UI too
				if (selectedDirectoriesToScan.Add(folder))
				{
					// Append the new folder to the TextBox, followed by a newline
					SelectedDirectoriesTextBox.Text += folder + Environment.NewLine;
				}
			}
		}
	}


	private void BrowseForXMLPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFile))
		{
			// The extra validations are required since user can provide path in the text box directly
			if (File.Exists(selectedFile) && (Path.GetExtension(selectedFile).Equals(".xml", StringComparison.OrdinalIgnoreCase)))
			{
				// Store the selected XML file path
				selectedXMLFilePath = selectedFile;

				// Update the TextBox with the selected XML file path
				BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
			}
			else
			{
				throw new InvalidOperationException($"Selected item '{selectedFile}' is not a valid XML file path");
			}
		}

	}


	#region Manage active step border

	private void SetBorderStyles(Border border)
	{

		// Create a LinearGradientBrush
		LinearGradientBrush linearGradientBrush = new()
		{
			StartPoint = new Windows.Foundation.Point(0, 0),
			EndPoint = new Windows.Foundation.Point(1, 1)
		};

		// Add Gradient Stops
		linearGradientBrush.GradientStops.Add(new GradientStop
		{
			Color = Colors.HotPink,
			Offset = 0
		});

		linearGradientBrush.GradientStops.Add(new GradientStop
		{
			Color = Colors.Wheat,
			Offset = 1
		});

		// apply the styles to the border
		border.BorderBrush = linearGradientBrush;
		border.BorderThickness = new Thickness(1);

		// Adjust the elevation of the border to achieve the shadow effect
		border.Translation += new Vector3(0, 0, 40);

		// Use the SharedShadow defined in XAML
		border.Shadow = sharedShadow;
	}

	private static void ResetBorderStyles(Border border)
	{
		// Reset the BorderBrush and BorderThickness to their default values
		border.BorderBrush = null;
		border.BorderThickness = new Thickness(0);

		// Reset the border depth
		border.Translation = new Vector3(0, 0, 0);

		border.Shadow = null;
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
			Step3InfoBar.Severity = InfoBarSeverity.Informational;
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
			if (fileIdentities.Count is 0)
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
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. fileIdentities.FileIdentitiesInternal], level: scanLevel);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, Authorization.Allow);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{selectedSupplementalPolicyName}.xml");

				// Set the BasePolicyID of our new policy to the one from user selected policy
				string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, selectedSupplementalPolicyName, _BasePolicyObject!.BasePolicyID, null);

				// Configure policy rule options
				if (!_IsSignedPolicy)
				{
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);
				}
				else
				{
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy]);
				}

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				if (_IsSignedPolicy)
				{
					// Add certificate's details to the supplemental policy
					_ = AddSigningDetails.Add(EmptyPolicyPath, _CertPath!);
				}

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				// If user selected to deploy the policy
				if (deployPolicy)
				{
					string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

					if (_IsSignedPolicy)
					{
						string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip.p7");

						// Convert the XML file to CIP
						PolicyToCIPConverter.Convert(OutputPath, CIPPath);

						// Sign the CIP
						SignToolHelper.Sign(new FileInfo(CIPPath), new FileInfo(_SignToolPath!), _CertCN!);

						// Rename the .p7 signed file to .cip
						File.Move(CIPp7SignedFilePath, CIPPath, true);
					}

					else
					{
						PolicyToCIPConverter.Convert(OutputPath, CIPPath);
					}

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

			// Clear the private variable after the policy is created. This allows the user to remove some items from the logs and recreate the policy with less data if needed.
			fileIdentities.FileIdentitiesInternal.Clear();
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


	/// <summary>
	/// Event handler for the clear button in the base policy path selection button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = null;
		selectedXMLFilePath = null;
		tempBasePolicyPath = null;
	}
}
