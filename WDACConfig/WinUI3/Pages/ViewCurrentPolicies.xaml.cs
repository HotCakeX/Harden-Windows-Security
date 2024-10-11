using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class ViewCurrentPolicies : Page
    {
        // Store the original list of policies
        private List<WDACConfig.CiPolicyInfo> AllPolicies = [];

        // Keep track of the currently selected policy
        private WDACConfig.CiPolicyInfo? selectedPolicy;

        public ViewCurrentPolicies()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

            // Initially disable the RemoveUnsignedPolicy button
            RemoveUnsignedPolicy.IsEnabled = false;
        }

        // Event handler for the RetrievePoliciesButton click
        private async void RetrievePoliciesButton_Click(object sender, RoutedEventArgs e)
        {
            // Disable the button to prevent multiple clicks while retrieving
            RetrievePoliciesButton.IsEnabled = false;

            // The checkboxes belong to the UI thread so can't use their bool value directly on the Task.Run's thread
            bool ShouldIncludeSystem = IncludeSystemPolicies.IsChecked ?? false;
            bool ShouldIncludeBase = IncludeBasePolicies.IsChecked ?? false;
            bool ShouldIncludeSupplemental = IncludeSupplementalPolicies.IsChecked ?? false;

            // Run the GetPolicies method asynchronously
            List<WDACConfig.CiPolicyInfo> policies = await Task.Run(() => WDACConfig.CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental));

            // Update the UI once the task completes
            PoliciesCountTextBlock.Text = $"Number of Policies: {policies.Count}";

            // Store the complete list of policies
            AllPolicies = policies;

            // Display the retrieved policies
            PoliciesListView.ItemsSource = AllPolicies;

            // Re-enable the button
            RetrievePoliciesButton.IsEnabled = true;
        }


        // Event handler for the search box text change
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string filter = SearchBox.Text.Trim().ToLowerInvariant();

            // Filter the policies based on the search input
            var filteredPolicies = AllPolicies.Where(p =>
                (p.PolicyID?.ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.FriendlyName?.ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.VersionString?.ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.IsSystemPolicy.ToString().ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsSignedPolicy.ToString().ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsOnDisk.ToString().ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.IsEnforced.ToString().ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
                (p.PolicyOptionsDisplay?.ToLowerInvariant().Contains(filter, System.StringComparison.OrdinalIgnoreCase) ?? false)
            ).ToList();

            // Display the filtered list
            PoliciesListView.ItemsSource = filteredPolicies;

            // Update the policies count text
            PoliciesCountTextBlock.Text = $"Number of Policies: {filteredPolicies.Count}";
        }

        // Event handler for when a policy is selected from the ListView
        private void PoliciesListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Get the selected policy from the ListView
            selectedPolicy = (WDACConfig.CiPolicyInfo)PoliciesListView.SelectedItem;

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
                        var result = await dialog.ShowAsync();

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

                // Remove the policy from the list and update the ListView
                _ = AllPolicies.Remove(selectedPolicy);

                // Reset ItemsSource to refresh the ListView
                PoliciesListView.ItemsSource = null;

                // Display the updated list of policies
                PoliciesListView.ItemsSource = AllPolicies;

                // Update the policies count text
                PoliciesCountTextBlock.Text = $"Number of Policies: {AllPolicies.Count}";

                // Disable the RemoveUnsignedPolicy button as the policy is no longer selected
                RemoveUnsignedPolicy.IsEnabled = false;
            }
        }

    }
}
