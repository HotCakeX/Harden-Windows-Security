using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Globalization;

namespace WDACConfig.Pages
{
    public sealed partial class GetSecurePolicySettings : Page
    {
        public GetSecurePolicySettings()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        // Event handler for the Fetch button
        private void InvokeButton_Click(object sender, RoutedEventArgs e)
        {
            // Retrieve input values
            string provider = ProviderTextBox.Text;
            string key = KeyTextBox.Text;
            string valueName = ValueNameTextBox.Text;

            // Check if all fields are filled
            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(valueName))
            {
                InfoBar.Message = "Please fill in all three fields.";
                InfoBar.Severity = InfoBarSeverity.Warning;
                InfoBar.Title = "Input Required";
                InfoBar.IsOpen = true;
                return;
            }

            // Call the Invoke method
            SecurePolicySetting result = GetCIPolicySetting.Invoke(provider, key, valueName);

            if (result.StatusCode != 0)
            {
                InfoBar.Message = "There is no policy deployed on the system that contains the selected secure setting.";
                InfoBar.Severity = InfoBarSeverity.Informational;
                InfoBar.Title = "Policy not found";
                InfoBar.IsOpen = true;
            }
            else
            {
                InfoBar.Message = "A policy with the selected secure setting details is currently deployed on the system.";
                InfoBar.Severity = InfoBarSeverity.Success;
                InfoBar.Title = "Policy found";
                InfoBar.IsOpen = true;
            }

            // Populate result fields
            ValueTextBox.Text = result.Value?.ToString();
            ValueTypeTextBox.Text = result.ValueType.ToString();
            ValueSizeTextBox.Text = result.ValueSize.ToString(CultureInfo.InvariantCulture);
            StatusTextBox.Text = result.Status.ToString();
            StatusCodeTextBox.Text = result.StatusCode.ToString(CultureInfo.InvariantCulture);
        }
    }
}
