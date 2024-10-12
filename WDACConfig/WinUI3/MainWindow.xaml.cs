using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace WDACConfig
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            this.InitializeComponent();

            // https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
            // Make title bar Mica
            ExtendsContentIntoTitleBar = true;
        }

        // Event handler for the main navigation menu
        private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            // Check if the item is selected
            if (args.SelectedItem is NavigationViewItem selectedItem)
            {
                string? selectedTag = selectedItem.Tag?.ToString();

                // Navigate to the page based on the Tag
                switch (selectedTag)
                {
                    case "Home":
                        _ = ContentFrame.Navigate(typeof(Pages.Home));
                        break;
                    case "CreatePolicy":
                        _ = ContentFrame.Navigate(typeof(Pages.CreatePolicy));
                        break;
                    case "GetCIHashes":
                        _ = ContentFrame.Navigate(typeof(Pages.GetCIHashes));
                        break;
                    // Doesn't need XAML nav item because it's included by default in the navigation view
                    case "Settings":
                        _ = ContentFrame.Navigate(typeof(Pages.Settings));
                        break;
                    case "GitHubDocumentation":
                        _ = ContentFrame.Navigate(typeof(Pages.GitHubDocumentation));
                        break;
                    case "MicrosoftDocumentation":
                        _ = ContentFrame.Navigate(typeof(Pages.MicrosoftDocumentation));
                        break;
                    case "GetSecurePolicySettings":
                        _ = ContentFrame.Navigate(typeof(Pages.GetSecurePolicySettings));
                        break;
                    case "ViewCurrentPolicies":
                        _ = ContentFrame.Navigate(typeof(Pages.ViewCurrentPolicies));
                        break;
                    case "ConfigurePolicyRuleOptions":
                        _ = ContentFrame.Navigate(typeof(Pages.ConfigurePolicyRuleOptions));
                        break;
                    case "Logs":
                        _ = ContentFrame.Navigate(typeof(Pages.Logs));
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
