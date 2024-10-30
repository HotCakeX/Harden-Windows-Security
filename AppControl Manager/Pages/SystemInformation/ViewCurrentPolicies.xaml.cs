using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class ViewCurrentPolicies : Page
    {
        // To store the policies displayed on the DataGrid
        public ObservableCollection<CiPolicyInfo> AllPolicies { get; set; }

        // Store all outputs for searching
        private List<CiPolicyInfo> AllPoliciesOutput;

        // Keep track of the currently selected policy
        private CiPolicyInfo? selectedPolicy;

        public ViewCurrentPolicies()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

            // Initially disable the RemoveUnsignedPolicy button
            RemoveUnsignedPolicy.IsEnabled = false;

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

            // Check if a policy was actually selected and if it's unsigned
            if (selectedPolicy is not null && !selectedPolicy.IsSignedPolicy)
            {
                // Enable the RemoveUnsignedPolicy button for unsigned policies
                RemoveUnsignedPolicy.IsEnabled = true;
            }
            else
            {
                // Disable the button if no unsigned policy is selected
                RemoveUnsignedPolicy.IsEnabled = false;
            }
        }



        // Event handler for the RemoveUnsignedPolicy button click
        private async void RemoveUnsignedPolicy_Click(object sender, RoutedEventArgs e)
        {

            // Disable the remove button while the selected policy is being processed
            // It will stay disabled until user selected another removable policy
            RemoveUnsignedPolicy.IsEnabled = false;

            string AppControlPolicyName = "AppControlManagerSupplementalPolicy";

            // Make sure we have a valid selected policy that is unsigned
            if (selectedPolicy is not null && !selectedPolicy.IsSignedPolicy)
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


                // Remove the selected unsigned policy using the CiToolHelper
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
                AllPolicies = new ObservableCollection<CiPolicyInfo>(
                    collectionToSort.OrderByDescending(keySelector)
                );

                // Set the column direction to Descending
                e.Column.SortDirection = DataGridSortDirection.Descending;
            }
            else
            {
                // Ascending: custom order depending on column type
                AllPolicies = new ObservableCollection<CiPolicyInfo>(
                    collectionToSort.OrderBy(keySelector)
                );
                e.Column.SortDirection = DataGridSortDirection.Ascending;
            }

            // Update the ItemsSource of the DataGrid
            DeployedPolicies.ItemsSource = AllPolicies;
        }
    }
}
