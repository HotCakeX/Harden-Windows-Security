using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class ViewCurrentPolicies : Page
    {
        public ViewCurrentPolicies()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

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

            // Bind the policies to the ListView
            PoliciesListView.ItemsSource = policies;

            // Re-enable the button
            RetrievePoliciesButton.IsEnabled = true;
        }
    }
}
