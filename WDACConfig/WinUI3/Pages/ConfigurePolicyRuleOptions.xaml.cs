using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml;
using System.Collections.Generic;
using System.Linq;

namespace WDACConfig.Pages
{
    public sealed partial class ConfigurePolicyRuleOptions : Page
    {
        // Property to hold the keys of the PolicyRuleOptionsActual dictionary
        public List<string> PolicyRuleOptionsKeys { get; set; }

        public ConfigurePolicyRuleOptions()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

            // Initialize the keys property with dictionary keys
            PolicyRuleOptionsKeys = WDACConfig.CiRuleOptions.PolicyRuleOptionsActual.Keys.ToList();

            // Set the TreeViews' ItemsSource
            RulesToAdd.ItemsSource = PolicyRuleOptionsKeys;
            RulesToRemove.ItemsSource = PolicyRuleOptionsKeys;
        }

        private void PickPolicyFileButton_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFile = WDACConfig.FileSystemPicker.ShowFilePicker(
                "Choose a Configuration File", ("XML Files", "*.xml"));

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Handle file processing here
            }
        }
    }
}
