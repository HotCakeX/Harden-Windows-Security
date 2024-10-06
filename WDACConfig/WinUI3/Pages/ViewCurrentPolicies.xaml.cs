using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class ViewCurrentPolicies : Page
    {

        // Store the original list of policies
        private List<WDACConfig.CiPolicyInfo> AllPolicies = [];

        public ViewCurrentPolicies()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

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

    }
}
