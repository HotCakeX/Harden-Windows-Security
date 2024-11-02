using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig
{
    public sealed partial class MainWindow : Window
    {
        public MainWindowViewModel ViewModel { get; }

        public MainWindow()
        {
            this.InitializeComponent();

            // https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
            // Make title bar Mica
            ExtendsContentIntoTitleBar = true;

            #region

            // Use the singleton instance of AppUpdate class
            AppUpdate updateService = AppUpdate.Instance;

            // Pass the AppUpdate class instance to MainWindowViewModel
            ViewModel = new MainWindowViewModel(updateService);

            // Set the DataContext of the Grid to enable bindings in XAML
            RootGrid.DataContext = ViewModel;

            _ = Task.Run(() =>
               {

                   // If AutoUpdateCheck is enabled in the user configurations, checks for updates on startup and displays a dot on the Update page in the navigation
                   // If a new version is available.
                   if (UserConfiguration.Get().AutoUpdateCheck == true)
                   {

                       Logger.Write("Checking for update on startup because AutoUpdateCheck is enabled");

                       // Start the update check
                       UpdateCheckResponse updateCheckResponse = updateService.Check();

                       // If a new version is available
                       if (updateCheckResponse.IsNewVersionAvailable)
                       {
                           // Set the text for the button in the update page
                           GlobalVars.updateButtonTextOnTheUpdatePage = $"Install version {updateCheckResponse.OnlineVersion}";
                       }
                       else
                       {
                           Logger.Write("No new version of the AppControl Manager is available.");
                       }
                   }

               });

            #endregion


            // Navigate to the CreatePolicy page when the window is loaded
            _ = ContentFrame.Navigate(typeof(Pages.CreatePolicy));

            // Set the "CreatePolicy" item as selected in the NavigationView
            MainNavigation.SelectedItem = MainNavigation.MenuItems.OfType<NavigationViewItem>()
                .First(item => item.Tag.ToString() == "CreatePolicy");
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
                    case "SystemInformation":
                        _ = ContentFrame.Navigate(typeof(Pages.SystemInformation));
                        break;
                    case "ConfigurePolicyRuleOptions":
                        _ = ContentFrame.Navigate(typeof(Pages.ConfigurePolicyRuleOptions));
                        break;
                    case "Logs":
                        _ = ContentFrame.Navigate(typeof(Pages.Logs));
                        break;
                    case "Simulation":
                        _ = ContentFrame.Navigate(typeof(Pages.Simulation));
                        break;
                    case "Update":
                        _ = ContentFrame.Navigate(typeof(Pages.Update));
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
