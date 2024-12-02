using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;

namespace WDACConfig.Pages
{
    public sealed partial class ViewCurrentPolicies : Page
    {
        // To store the policies displayed on the DataGrid
        public ObservableCollection<CiPolicyInfo> AllPolicies { get; set; }

        // Store all outputs for searching
        private readonly List<CiPolicyInfo> AllPoliciesOutput;

        // Keep track of the currently selected policy
        private CiPolicyInfo? selectedPolicy;

        public ViewCurrentPolicies()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Initially disable the RemoveUnsignedOrSupplementalPolicyButton
            RemoveUnsignedOrSupplementalPolicyButton.IsEnabled = false;

            AllPolicies = [];
            AllPoliciesOutput = [];
        }

        // Event handler for the RetrievePoliciesButton click
        private async void RetrievePoliciesButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {

                // Disable the button to prevent multiple clicks while retrieving
                RetrievePoliciesButton.IsEnabled = false;

                // Clear the policies before getting and showing the new ones
                AllPolicies.Clear();
                AllPoliciesOutput.Clear();

                // The checkboxes belong to the UI thread so can't use their bool value directly on the Task.Run's thread
                bool ShouldIncludeSystem = IncludeSystemPolicies.IsChecked ?? false;
                bool ShouldIncludeBase = IncludeBasePolicies.IsChecked ?? false;
                bool ShouldIncludeSupplemental = IncludeSupplementalPolicies.IsChecked ?? false;

                // Run the GetPolicies method asynchronously
                List<CiPolicyInfo> policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental));

                // Store all of the policies in the ObservableCollection
                foreach (CiPolicyInfo policy in policies)
                {
                    CiPolicyInfo pol = new()
                    {
                        PolicyID = policy.PolicyID,
                        BasePolicyID = policy.BasePolicyID,
                        FriendlyName = policy.FriendlyName,
                        Version = policy.Version,
                        IsAuthorized = policy.IsAuthorized,
                        IsEnforced = policy.IsEnforced,
                        IsOnDisk = policy.IsOnDisk,
                        IsSignedPolicy = policy.IsSignedPolicy,
                        IsSystemPolicy = policy.IsSystemPolicy,
                        PolicyOptions = policy.PolicyOptions
                    };

                    // Add to the list
                    AllPoliciesOutput.Add(pol);

                    // Add to the ObservableCollection bound to the UI
                    _ = DispatcherQueue.TryEnqueue(() =>
                    {
                        AllPolicies.Add(pol);
                    });
                }

                // Update the UI once the task completes
                PoliciesCountTextBlock.Text = $"Number of Policies: {policies.Count}";

                DeployedPolicies.ItemsSource = AllPolicies;
            }

            finally
            {
                // Re-enable the button
                RetrievePoliciesButton.IsEnabled = true;
            }
        }


        // Event handler for the search box text change
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

            // Perform a case-insensitive search in all relevant fields
            List<CiPolicyInfo> filteredResults = AllPoliciesOutput.Where(p =>
                (p.PolicyID?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.FriendlyName?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.VersionString?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.IsSystemPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsSignedPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsOnDisk.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsEnforced.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.PolicyOptionsDisplay?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
            ).ToList();

            // Update the ObservableCollection on the UI thread with the filtered results
            AllPolicies.Clear();
            foreach (CiPolicyInfo result in filteredResults)
            {
                AllPolicies.Add(result);
            }

            // Update the policies count text
            PoliciesCountTextBlock.Text = $"Number of Policies: {filteredResults.Count}";
        }


        // Event handler for when a policy is selected from the DataGrid
        private void DeployedPolicies_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

            // Get the selected policy from the DataGrid
            selectedPolicy = (CiPolicyInfo)DeployedPolicies.SelectedItem;

            // Check if a non-system policy was actually selected and if it's unsigned or supplemental and if it exists on the disk
            if (selectedPolicy is not null && !selectedPolicy.IsSystemPolicy && selectedPolicy.IsOnDisk && (!selectedPolicy.IsSignedPolicy || !string.Equals(selectedPolicy.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase)))
            {
                // Enable the RemoveUnsignedOrSupplementalPolicyButton for unsigned policies
                RemoveUnsignedOrSupplementalPolicyButton.IsEnabled = true;
            }
            else
            {
                // Disable the button if no unsigned policy is selected
                RemoveUnsignedOrSupplementalPolicyButton.IsEnabled = false;
            }
        }



        /// <summary>
        /// Event handler for the RemoveUnsignedOrSupplementalPolicyButton click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void RemoveUnsignedOrSupplementalPolicy_Click(object sender, RoutedEventArgs e)
        {

            // Disable the remove button while the selected policy is being processed
            // It will stay disabled until user selected another removable policy
            RemoveUnsignedOrSupplementalPolicyButton.IsEnabled = false;

            string AppControlPolicyName = "AppControlManagerSupplementalPolicy";

            // Make sure we have a valid selected non-system policy that is unsigned or supplemental and is on disk
            if (selectedPolicy is not null && !selectedPolicy.IsSystemPolicy && selectedPolicy.IsOnDisk && (!selectedPolicy.IsSignedPolicy || !string.Equals(selectedPolicy.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase)))
            {

                // Check if the selected policy has the FriendlyName "AppControlManagerSupplementalPolicy"
                if (string.Equals(selectedPolicy.FriendlyName, AppControlPolicyName, StringComparison.OrdinalIgnoreCase))
                {

                    // Get all the deployed base policies
                    List<string?> CurrentlyDeployedPolicy = CiToolHelper.GetPolicies(false, true, false).Select(p => p.BasePolicyID).ToList();

                    // Check if the base policies of the AppControlManagerSupplementalPolicy Supplemental policy is currently deployed on the system
                    // And only then show the prompt, otherwise allow for its removal just like any other policy since it's a stray Supplemental policy
                    if (CurrentlyDeployedPolicy.Contains(selectedPolicy.BasePolicyID))
                    {

                        // Create and display a ContentDialog with Yes and No options
                        ContentDialog dialog = new()
                        {
                            Title = "Confirm Policy Removal",
                            Content = $"The policy '{AppControlPolicyName}' must not be removed because you won't be able to relaunch the AppControl Manager again. Are you sure you still want to remove it?",
                            PrimaryButtonText = "Yes",
                            CloseButtonText = "No",
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


                // Remove the selected unsigned/supplemental policy using the CiToolHelper
                await Task.Run(() => CiToolHelper.RemovePolicy(selectedPolicy.PolicyID!));

                // Update the UI or log the action
                Logger.Write($"Removed policy: {selectedPolicy.FriendlyName} with the PolicyID {selectedPolicy.PolicyID}");

                // Remove the policy from the list and update the DataGrid
                _ = AllPolicies.Remove(selectedPolicy);

                // Update the policies count text
                PoliciesCountTextBlock.Text = $"Number of Policies: {AllPolicies.Count}";
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
                { "Policy ID", CopyPolicyID_Click },
                { "Base Policy ID", CopyBasePolicyID_Click },
                { "Friendly Name", CopyFriendlyName_Click },
                { "Version", CopyVersion_Click },
                { "Is Authorized", CopyIsAuthorized_Click },
                { "Is Enforced", CopyIsEnforced_Click },
                { "Is On Disk", CopyIsOnDisk_Click },
                { "Is Signed Policy", CopyIsSignedPolicy_Click },
                { "Is System Policy", CopyIsSystemPolicy_Click },
                { "Policy Options", CopyPolicyOptionsDisplay_Click }
            };

            // Add menu items with specific click events for each column
            foreach (DataGridColumn column in DeployedPolicies.Columns)
            {
                string headerText = column.Header.ToString()!;

                if (copyActions.TryGetValue(headerText, out RoutedEventHandler? value))
                {
                    // Create a new MenuFlyout Item
                    MenuFlyoutItem menuItem = new() { Text = $"Copy {headerText}" };

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
                foreach (var selectedItem in DeployedPolicies.SelectedItems)
                {
                    if (selectedItem is CiPolicyInfo selectedRow)
                    {
                        // Append each row's formatted data to the StringBuilder
                        _ = dataBuilder.AppendLine(ConvertRowToText(selectedRow));

                        // Add a separator between rows for readability in multi-row copies
                        _ = dataBuilder.AppendLine(new string('-', 50));
                    }
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
                .AppendLine($"Policy ID: {row.PolicyID}")
                .AppendLine($"Base Policy ID: {row.BasePolicyID}")
                .AppendLine($"Friendly Name: {row.FriendlyName}")
                .AppendLine($"Version: {row.Version}")
                .AppendLine($"Is Authorized: {row.IsAuthorized}")
                .AppendLine($"Is Enforced: {row.IsEnforced}")
                .AppendLine($"Is On Disk: {row.IsOnDisk}")
                .AppendLine($"Is Signed Policy: {row.IsSignedPolicy}")
                .AppendLine($"Is System Policy: {row.IsSystemPolicy}")
                .AppendLine($"Policy Options: {row.PolicyOptionsDisplay}")
                .ToString();
        }


    }
}
