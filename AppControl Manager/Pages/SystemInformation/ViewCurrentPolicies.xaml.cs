using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicyIntel;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

public sealed partial class ViewCurrentPolicies : Page
{
	// To store the policies displayed on the DataGrid
	internal ObservableCollection<CiPolicyInfo> AllPolicies { get; set; }

	// Store all outputs for searching
	private readonly List<CiPolicyInfo> AllPoliciesOutput;

	// Keep track of the currently selected policy
	private CiPolicyInfo? selectedPolicy;

	public ViewCurrentPolicies()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Initially disable the RemovePolicyButton
		RemovePolicyButton.IsEnabled = false;

		AllPolicies = [];
		AllPoliciesOutput = [];
	}


	/// <summary>
	/// Event handler for the RetrievePoliciesButton click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void RetrievePoliciesButton_Click(object sender, RoutedEventArgs e)
	{
		RetrievePolicies();
	}


	/// <summary>
	/// Helper method to retrieve the policies from the system
	/// </summary>
	private async void RetrievePolicies()
	{

		try
		{

			// Disable the button to prevent multiple clicks while retrieving
			RetrievePoliciesButton.IsEnabled = false;

			// Clear the policies before getting and showing the new ones
			// They also set the "SelectedItem" property of the DataGrid to null
			AllPolicies.Clear();
			AllPoliciesOutput.Clear();

			// The checkboxes belong to the UI thread so can't use their bool value directly on the Task.Run's thread
			bool ShouldIncludeSystem = IncludeSystemPolicies.IsChecked;
			bool ShouldIncludeBase = IncludeBasePolicies.IsChecked;
			bool ShouldIncludeSupplemental = IncludeSupplementalPolicies.IsChecked;
			bool ShouldIncludeAppControlManagerSupplementalPolicy = IncludeAppControlManagerSupplementalPolicy.IsChecked;

			List<CiPolicyInfo> policies = [];

			// Check if the AppControlManagerSupplementalPolicy checkbox is checked, if it is, show the automatic policy
			if (ShouldIncludeAppControlManagerSupplementalPolicy)
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental));
			}
			// Filter out the AppControlManagerSupplementalPolicy automatic policies from the list
			else
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental).Where(x => !string.Equals(x.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase)).ToList());
			}

			// Store all of the policies in the ObservableCollection
			foreach (CiPolicyInfo policy in policies)
			{
				CiPolicyInfo temp = new()
				{
					PolicyID = policy.PolicyID,
					BasePolicyID = policy.BasePolicyID,
					FriendlyName = policy.FriendlyName,
					Version = policy.Version,
					VersionString = policy.VersionString,
					IsSystemPolicy = policy.IsSystemPolicy,
					IsSignedPolicy = policy.IsSignedPolicy,
					IsOnDisk = policy.IsOnDisk,
					IsEnforced = policy.IsEnforced,
					IsAuthorized = policy.IsAuthorized,
					PolicyOptions = policy.PolicyOptions
				};

				// Add the retrieved policies to the list in class instance
				AllPoliciesOutput.Add(temp);

				AllPolicies.Add(temp);
			}

			// Update the UI once the task completes
			PoliciesCountTextBlock.Text = GlobalVars.Rizz.GetString("NumberOfPolicies") + policies.Count;

			DeployedPolicies.ItemsSource = AllPolicies;
		}

		finally
		{
			// Re-enable the button
			RetrievePoliciesButton.IsEnabled = true;
		}
	}



	/// <summary>
	/// Event handler for the search box text change
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

		// Perform a case-insensitive search in all relevant fields
		List<CiPolicyInfo> filteredResults = [.. AllPoliciesOutput.Where(p =>
			(p.PolicyID?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FriendlyName?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.VersionString?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.IsSystemPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsSignedPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsOnDisk.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsEnforced.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.PolicyOptionsDisplay?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
		)];

		// Update the ObservableCollection on the UI thread with the filtered results
		AllPolicies.Clear();

		foreach (CiPolicyInfo result in filteredResults)
		{
			AllPolicies.Add(result);
		}

		// Update the policies count text
		PoliciesCountTextBlock.Text = GlobalVars.Rizz.GetString("NumberOfPolicies") + filteredResults.Count;
	}


	/// <summary>
	/// Event handler for when a policy is selected from the DataGrid. It will contain the selected policy.
	/// When the Refresh button is pressed, this event is fired again, but due to clearing the existing data in the refresh event handler, DataGrid's SelectedItem property will be null,
	/// so we detect it here and return from the method without assigning null to the selectedPolicy class instance.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void DeployedPolicies_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the selected policy from the DataGrid
		CiPolicyInfo? temp = (CiPolicyInfo)DeployedPolicies.SelectedItem;

		if (temp is null)
		{
			return;
		}

		selectedPolicy = temp;

		// Check if:
		if (
			// It's a non-system policy
			!selectedPolicy.IsSystemPolicy &&
			// It's available on disk
			selectedPolicy.IsOnDisk)
		{
			// Enable the RemovePolicyButton
			RemovePolicyButton.IsEnabled = true;
		}
		else
		{
			// Disable the button if no proper policy is selected
			RemovePolicyButton.IsEnabled = false;
		}

		// Enable the Swap Policy ComboBox only when the selected policy is a base type, unsigned and non-system
		SwapPolicyComboBox.IsEnabled = string.Equals(selectedPolicy.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && !selectedPolicy.IsSignedPolicy && !selectedPolicy.IsSystemPolicy;
	}



	/// <summary>
	/// Event handler for the RemovePolicyButton click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RemovePolicy_Click(object sender, RoutedEventArgs e)
	{

		List<CiPolicyInfo> policiesToRemove = [];

		try
		{
			// Disable the remove button while the selected policy is being processed
			// It will stay disabled until user selects another removable policy
			RemovePolicyButton.IsEnabled = false;

			// Disable interactions with the DataGrid while policies are being removed
			DeployedPolicies.IsHitTestVisible = false;

			// Disable the refresh policies button while policies are being removed
			RetrievePoliciesButton.IsEnabled = false;

			// Disable the search box while policies are being removed
			SearchBox.IsEnabled = false;

			// Make sure we have a valid selected non-system policy that is on disk
			if (selectedPolicy is not null && !selectedPolicy.IsSystemPolicy && selectedPolicy.IsOnDisk)
			{
				// List of all the deployed non-system policies
				List<CiPolicyInfo> currentlyDeployedPolicies = [];

				// List of all the deployed base policy IDs
				List<string?> currentlyDeployedBasePolicyIDs = [];

				// List of all the deployed AppControlManagerSupplementalPolicy
				List<CiPolicyInfo> currentlyDeployedAppControlManagerSupplementalPolicies = [];

				// Populate the lists defined above
				await Task.Run(() =>
				{
					currentlyDeployedPolicies = CiToolHelper.GetPolicies(false, true, true);

					currentlyDeployedBasePolicyIDs = [.. currentlyDeployedPolicies.Where(x => string.Equals(x.PolicyID, x.BasePolicyID, StringComparison.OrdinalIgnoreCase)).Select(p => p.BasePolicyID)];

					currentlyDeployedAppControlManagerSupplementalPolicies = [.. currentlyDeployedPolicies.Where(p => string.Equals(p.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];
				});


				// Check if the selected policy has the FriendlyName "AppControlManagerSupplementalPolicy"
				if (string.Equals(selectedPolicy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))
				{

					// Check if the base policy of the AppControlManagerSupplementalPolicy Supplemental policy is currently deployed on the system
					// And only then show the prompt, otherwise allow for its removal just like any other policy since it's a stray Supplemental policy
					if (currentlyDeployedBasePolicyIDs.Contains(selectedPolicy.BasePolicyID))
					{
						// Create and display a ContentDialog with Yes and No options
						ContentDialog dialog = new()
						{
							Title = GlobalVars.Rizz.GetString("WarningTitle"),
							Content = GlobalVars.Rizz.GetString("ManualRemovalWarning") + GlobalVars.AppControlManagerSpecialPolicyName + "' " + GlobalVars.Rizz.GetString("ManualRemovalWarningEnd"),
							PrimaryButtonText = GlobalVars.Rizz.GetString("Yes"),
							BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
							BorderThickness = new Thickness(1),
							CloseButtonText = GlobalVars.Rizz.GetString("No"),
							XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
						};

						// Show the dialog and wait for user response
						ContentDialogResult result = await dialog.ShowAsync();

						// If the user did not select "Yes", return from the method
						if (result is not ContentDialogResult.Primary)
						{
							return;
						}

					}
				}

				// Add the policy to the removal list
				policiesToRemove.Add(selectedPolicy);

				#region


				// If the policy that's going to be removed is a base policy
				if (string.Equals(selectedPolicy.PolicyID, selectedPolicy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
				{
					// Check if it's unsigned, Or it is signed but doesn't have the "Enabled:Unsigned System Integrity Policy" rule option
					// Meaning it was re-signed in unsigned mode and can be now safely removed
					if (!selectedPolicy.IsSignedPolicy || (selectedPolicy.IsSignedPolicy && selectedPolicy.PolicyOptions is not null && selectedPolicy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase)))
					{
						// Find any automatic AppControlManagerSupplementalPolicy that is associated with it and still on the system
						List<CiPolicyInfo> extraPoliciesToRemove = [.. currentlyDeployedAppControlManagerSupplementalPolicies.Where(p => string.Equals(p.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && p.IsOnDisk)];

						if (extraPoliciesToRemove.Count > 0)
						{
							foreach (CiPolicyInfo item in extraPoliciesToRemove)
							{
								policiesToRemove.Add(item);
							}
						}
					}
				}

				#endregion

				// If there are policies to be removed
				if (policiesToRemove.Count > 0)
				{

					DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyRemoval");


					foreach (CiPolicyInfo policy in policiesToRemove)
					{
						// Remove the policy directly from the system if it's unsigned or supplemental
						if (!policy.IsSignedPolicy || !string.Equals(policy.PolicyID, policy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
						{
							await Task.Run(() =>
							{
								CiToolHelper.RemovePolicy(policy.PolicyID!);
							});
						}

						// At this point the policy is definitely a Signed Base policy
						else
						{
							// If the EnabledUnsignedSystemIntegrityPolicy policy rule option exists
							// Which means 1st stage already happened
							if (policy.PolicyOptions is not null && policy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase))
							{
								// And if system was rebooted once after performing the 1st removal stage
								if (VerifyRemovalEligibility(policy.PolicyID!))
								{
									CiToolHelper.RemovePolicy(policy.PolicyID!);

									// Remove the PolicyID from the SignedPolicyStage1RemovalTimes dictionary
									UserConfiguration.RemoveSignedPolicyStage1RemovalTime(policy.PolicyID!);
								}
								else
								{
									// Create and display a ContentDialog
									ContentDialog dialog = new()
									{
										Title = GlobalVars.Rizz.GetString("WarningTitle"),
										Content = GlobalVars.Rizz.GetString("RestartRequired") + policy.FriendlyName + "' " + GlobalVars.Rizz.GetString("RestartRequiredEnd") + policy.PolicyID + "')",
										PrimaryButtonText = GlobalVars.Rizz.GetString("Understand"),
										BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
										BorderThickness = new Thickness(1),
										XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
									};

									// Show the dialog and wait for user response
									_ = await dialog.ShowAsync();

									// Exit the method, nothing more can be done about the selected policy
									return;
								}
							}

							// Treat it as a new signed policy removal
							else
							{


								#region Signing Details acquisition

								string CertCN;
								string CertPath;
								string SignToolPath;
								string XMLPolicyPath;

								// Instantiate the Content Dialog
								SigningDetailsDialogForRemoval customDialog = new(currentlyDeployedBasePolicyIDs, policy.PolicyID!);

								// Show the dialog and await its result
								ContentDialogResult result = await customDialog.ShowAsync();

								// Ensure primary button was selected
								if (result is ContentDialogResult.Primary)
								{
									SignToolPath = customDialog.SignToolPath!;
									CertPath = customDialog.CertificatePath!;
									CertCN = customDialog.CertificateCommonName!;
									XMLPolicyPath = customDialog.XMLPolicyPath!;

									// Sometimes the content dialog lingers on or re-appears so making sure it hides
									customDialog.Hide();

								}
								else
								{
									return;
								}

								#endregion

								// Add the unsigned policy rule option to the policy
								CiRuleOptions.Set(filePath: XMLPolicyPath, rulesToAdd: [SiPolicy.OptionType.EnabledUnsignedSystemIntegrityPolicy]);

								// Making sure SupplementalPolicySigners do not exist in the XML policy
								CiPolicyHandler.RemoveSupplementalSigners(XMLPolicyPath);

								// Define the path for the CIP file
								string randomString = GUIDGenerator.GenerateUniqueGUID();
								string xmlFileName = Path.GetFileName(XMLPolicyPath);
								string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

								string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

								// Convert the XML file to CIP, overwriting the unsigned one
								PolicyToCIPConverter.Convert(XMLPolicyPath, CIPFilePath);

								// Sign the CIP
								SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

								// Rename the .p7 signed file to .cip
								File.Move(CIPp7SignedFilePath, CIPFilePath, true);

								// Deploy the signed CIP file
								CiToolHelper.UpdatePolicy(CIPFilePath);

								SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(XMLPolicyPath, null);

								// The time of first stage of the signed policy removal
								// Since policy object has the full ID, in upper case with curly brackets,
								// We need to normalize them to match what the CiPolicyInfo class uses
								UserConfiguration.AddSignedPolicyStage1RemovalTime(policyObj.PolicyID.Trim('{', '}').ToLowerInvariant(), DateTime.UtcNow);
							}
						}
					}
				}
			}
		}

		finally
		{
			// Refresh the DataGrid's policies and their count
			RetrievePolicies();

			DeployedPolicies.IsHitTestVisible = true;
			RetrievePoliciesButton.IsEnabled = true;
			SearchBox.IsEnabled = true;
		}
	}


	// https://learn.microsoft.com/en-us/windows/communitytoolkit/controls/datagrid_guidance/group_sort_filter
	// Column sorting logic for the entire DataGrid
	private void DeployedPoliciesDataGrid_Sorting(object sender, DataGridColumnEventArgs e)
	{
		// Sort the column based on its tag and current sort direction
		if (string.Equals(e.Column.Tag?.ToString(), "IsAuthorized", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.IsAuthorized);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "IsEnforced", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.IsEnforced);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "IsOnDisk", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.IsOnDisk);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "IsSignedPolicy", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.IsSignedPolicy);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "IsSystemPolicy", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.IsSystemPolicy);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "Version", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.Version);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "FriendlyName", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.FriendlyName);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "PolicyID", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.PolicyID);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "BasePolicyID", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.BasePolicyID);
		}
		else if (string.Equals(e.Column.Tag?.ToString(), "PolicyOptionsDisplay", StringComparison.OrdinalIgnoreCase))
		{
			SortColumn(e, output => output.PolicyOptionsDisplay);
		}

		// Clear SortDirection for other columns
		foreach (DataGridColumn column in DeployedPolicies.Columns)
		{
			if (column != e.Column)
			{
				column.SortDirection = null;
			}
		}
	}

	// Helper method for sorting any column
	private void SortColumn<T>(DataGridColumnEventArgs e, Func<CiPolicyInfo, T> keySelector)
	{
		// Check if the search box is empty or not
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);

		// Get the collection to sort based on the search box status
		// Allowing us to sort only the items in the search results
		List<CiPolicyInfo> collectionToSort = isSearchEmpty ? AllPoliciesOutput : [.. AllPolicies];

		// Perform the sorting based on the current SortDirection (ascending or descending)
		if (e.Column.SortDirection is null || e.Column.SortDirection == DataGridSortDirection.Ascending)
		{
			// Descending: custom order depending on column type
			AllPolicies = [.. collectionToSort.OrderByDescending(keySelector)];

			// Set the column direction to Descending
			e.Column.SortDirection = DataGridSortDirection.Descending;
		}
		else
		{
			// Ascending: custom order depending on column type
			AllPolicies = [.. collectionToSort.OrderBy(keySelector)];
			e.Column.SortDirection = DataGridSortDirection.Ascending;
		}

		// Update the ItemsSource of the DataGrid
		DeployedPolicies.ItemsSource = AllPolicies;
	}



	/// <summary>
	/// Event handler for the Copy Individual Items SubMenu. It will populate the submenu items in the flyout of the data grid.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void DeployedPoliciesDataGrid_Loaded(object sender, RoutedEventArgs e)
	{
		// Ensure the CopyIndividualItemsSubMenu is available
		if (CopyIndividualItemsSubMenu is null)
		{
			return;
		}

		// Clear any existing items to avoid duplication if reloaded
		CopyIndividualItemsSubMenu.Items.Clear();

		// Create a dictionary to map headers to their specific click event methods
		Dictionary<string, RoutedEventHandler> copyActions = new()
		{
			{ GlobalVars.Rizz.GetString("PolicyIDHeader"), CopyPolicyID_Click },
			{ GlobalVars.Rizz.GetString("BasePolicyIDHeader"), CopyBasePolicyID_Click },
			{ GlobalVars.Rizz.GetString("FriendlyNameHeader"), CopyFriendlyName_Click },
			{ GlobalVars.Rizz.GetString("VersionHeader"), CopyVersion_Click },
			{ GlobalVars.Rizz.GetString("IsAuthorizedHeader"), CopyIsAuthorized_Click },
			{ GlobalVars.Rizz.GetString("IsEnforcedHeader"), CopyIsEnforced_Click },
			{ GlobalVars.Rizz.GetString("IsOnDiskHeader"), CopyIsOnDisk_Click },
			{ GlobalVars.Rizz.GetString("IsSignedPolicyHeader"), CopyIsSignedPolicy_Click },
			{ GlobalVars.Rizz.GetString("IsSystemPolicyHeader"), CopyIsSystemPolicy_Click },
			{ GlobalVars.Rizz.GetString("PolicyOptionsHeader"), CopyPolicyOptionsDisplay_Click }
		};

		// Add menu items with specific click events for each column
		foreach (DataGridColumn column in DeployedPolicies.Columns)
		{
			string headerText = column.Header.ToString()!;

			if (copyActions.TryGetValue(headerText, out RoutedEventHandler? value))
			{
				// Create a new MenuFlyout Item
				MenuFlyoutItem menuItem = new() { Text = GlobalVars.Rizz.GetString("Copy") + headerText };

				// Set the click event for the menu item
				menuItem.Click += value;

				// Add the menu item to the submenu
				CopyIndividualItemsSubMenu.Items.Add(menuItem);
			}
		}
	}

	// Click event handlers for each property
	private void CopyPolicyID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyID?.ToString());
	private void CopyBasePolicyID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.BasePolicyID?.ToString());
	private void CopyFriendlyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FriendlyName);
	private void CopyVersion_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Version?.ToString());
	private void CopyIsAuthorized_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsAuthorized.ToString());
	private void CopyIsEnforced_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsEnforced.ToString());
	private void CopyIsOnDisk_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsOnDisk.ToString());
	private void CopyIsSignedPolicy_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsSignedPolicy.ToString());
	private void CopyIsSystemPolicy_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsSystemPolicy.ToString());
	private void CopyPolicyOptionsDisplay_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyOptionsDisplay);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<CiPolicyInfo, string?> getProperty)
	{
		if (DeployedPolicies.SelectedItem is CiPolicyInfo selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				DataPackage dataPackage = new();
				dataPackage.SetText(propertyValue);
				Clipboard.SetContent(dataPackage);
			}
		}
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void DataGridFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the DataGrid
		if (DeployedPolicies.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the DataGrid
			foreach (CiPolicyInfo selectedItem in DeployedPolicies.SelectedItems)
			{
				// Append each row's formatted data to the StringBuilder
				_ = dataBuilder.AppendLine(ConvertRowToText(selectedItem));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(new string('-', 50));
			}

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}

	/// <summary>
	/// Converts the properties of a CiPolicyInfo row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected CiPolicyInfo row from the DataGrid.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(CiPolicyInfo row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.Rizz.GetString("PolicyIDLabel") + row.PolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("BasePolicyIDLabel") + row.BasePolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("FriendlyNameLabel") + row.FriendlyName)
			.AppendLine(GlobalVars.Rizz.GetString("VersionLabel") + row.Version)
			.AppendLine(GlobalVars.Rizz.GetString("IsAuthorizedLabel") + row.IsAuthorized)
			.AppendLine(GlobalVars.Rizz.GetString("IsEnforcedLabel") + row.IsEnforced)
			.AppendLine(GlobalVars.Rizz.GetString("IsOnDiskLabel") + row.IsOnDisk)
			.AppendLine(GlobalVars.Rizz.GetString("IsSignedPolicyLabel") + row.IsSignedPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("IsSystemPolicyLabel") + row.IsSystemPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("PolicyOptionsLabel") + row.PolicyOptionsDisplay)
			.ToString();
	}


#pragma warning disable CA1822

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

#pragma warning restore CA1822


	/// <summary>
	/// If returns true, the signed policy can be removed
	/// </summary>
	/// <param name="policyID"></param>
	/// <returns></returns>
	private static bool VerifyRemovalEligibility(string policyID)
	{
		// When system was last reboot
		DateTime lastRebootTimeUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

		Logger.Write(GlobalVars.Rizz.GetString("LastRebootTime") + lastRebootTimeUtc + " (UTC)");

		// When the policy's 1st stage was completed
		DateTime? stage1RemovalTime = UserConfiguration.QuerySignedPolicyStage1RemovalTime(policyID);

		if (stage1RemovalTime is not null)
		{
			Logger.Write(GlobalVars.Rizz.GetString("PolicyStage1Completed") + policyID + "' " + GlobalVars.Rizz.GetString("CompletedAt") + stage1RemovalTime + " (UTC)");

			if (stage1RemovalTime < lastRebootTimeUtc)
			{
				Logger.Write(GlobalVars.Rizz.GetString("PolicySafeToRemove"));

				return true;
			}
		}

		return false;
	}


	/// <summary>
	/// Event handler for when the Swap Policy ComboBox's selection changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SwapPolicyComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (selectedPolicy is null)
		{
			return;
		}

		bool reEnableButtonAtTheEnd = true;

		try
		{
			SwapPolicyComboBox.IsEnabled = false;
			RemovePolicyButton.IsEnabled = false;
			RetrievePoliciesButton.IsEnabled = false;
			SearchBox.IsEnabled = false;
			DeployedPolicies.IsEnabled = false;

			string policyID = selectedPolicy.PolicyID!.ToString();

			TextBlock formattedTextBlock = new()
			{
				TextWrapping = TextWrapping.WrapWholeWords,
				IsTextSelectionEnabled = true
			};

			SolidColorBrush violetBrush = new(Colors.Violet);
			SolidColorBrush hotPinkBrush = new(Colors.HotPink);

			// Create normal text runs
			Run normalText1 = new() { Text = GlobalVars.Rizz.GetString("SelectedPolicyName") };
			Run normalText2 = new() { Text = GlobalVars.Rizz.GetString("AndID") };
			Run normalText3 = new() { Text = GlobalVars.Rizz.GetString("WillBeChangedTo") };
			Run normalText4 = new() { Text = GlobalVars.Rizz.GetString("PolicyRedeployInfo") };

			// Create colored runs
			Run accentPolicyName = new() { Text = selectedPolicy.FriendlyName, Foreground = violetBrush };
			Run accentPolicyID = new() { Text = policyID, Foreground = violetBrush };
			Run accentPolicyType = new() { Text = ((ComboBoxItem)SwapPolicyComboBox.SelectedItem).Content.ToString(), Foreground = hotPinkBrush };

			// Create bold text run
			Bold boldText = new();
			boldText.Inlines.Add(new Run() { Text = GlobalVars.Rizz.GetString("SupplementalPolicyContinues") });

			// Add runs to the TextBlock
			formattedTextBlock.Inlines.Add(normalText1);
			formattedTextBlock.Inlines.Add(accentPolicyName);
			formattedTextBlock.Inlines.Add(normalText2);
			formattedTextBlock.Inlines.Add(accentPolicyID);
			formattedTextBlock.Inlines.Add(normalText3);
			formattedTextBlock.Inlines.Add(accentPolicyType);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(normalText4);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(boldText);

			// Create and display a ContentDialog with styled TextBlock
			ContentDialog dialog = new()
			{
				Title = GlobalVars.Rizz.GetString("SwappingPolicyTitle"),
				Content = formattedTextBlock,
				PrimaryButtonText = GlobalVars.Rizz.GetString("OK"),
				BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
				BorderThickness = new Thickness(1),
				CloseButtonText = GlobalVars.Rizz.GetString("Cancel"),
				XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
			};

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			// If the user did not select "OK", return from the method
			if (result is not ContentDialogResult.Primary)
			{
				reEnableButtonAtTheEnd = false;
				return;
			}

			int selectedIndex = SwapPolicyComboBox.SelectedIndex;

			await Task.Run(() =>
			{

				string stagingArea = StagingArea.NewStagingArea("PolicySwapping").FullName;

				switch (selectedIndex)
				{
					case 0: // Default Windows
						{
							BasePolicyCreator.BuildDefaultWindows(stagingArea,
								false,
								null,
								true,
								false,
								false,
								false,
								false,
								policyID
							);

							break;
						}
					case 1: // Allow Microsoft
						{
							BasePolicyCreator.BuildAllowMSFT(stagingArea,
								false,
								null,
								true,
								false,
								false,
								false,
								false,
								policyID
							);

							break;
						}
					case 2: // Signed and Reputable
						{
							BasePolicyCreator.BuildSignedAndReputable(stagingArea,
								false,
								null,
								true,
								false,
								false,
								false,
								false,
								policyID
							);

							break;
						}
					case 3: // Strict Kernel-Mode
						{
							BasePolicyCreator.BuildStrictKernelMode(stagingArea, false, false, true, policyID);

							break;
						}
					case 4: // Strict Kernel-Mode(No Flight Roots)
						{
							BasePolicyCreator.BuildStrictKernelMode(stagingArea, false, true, true, policyID);

							break;
						}
					default:
						{
							break;
						}
				}
			});
		}
		finally
		{
			// Refresh the DataGrid's policies and their count
			RetrievePolicies();

			if (reEnableButtonAtTheEnd)
			{
				SwapPolicyComboBox.IsEnabled = true;
			}

			RemovePolicyButton.IsEnabled = true;
			RetrievePoliciesButton.IsEnabled = true;
			SearchBox.IsEnabled = true;
			DeployedPolicies.IsEnabled = true;
		}

	}

}
