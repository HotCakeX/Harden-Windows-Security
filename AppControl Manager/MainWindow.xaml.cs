using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WDACConfig
{
    public sealed partial class MainWindow : Window
    {

        public MainWindowViewModel ViewModel { get; }

        // Dictionary to store the display names and associated NavigationViewItems
        private readonly Dictionary<string, NavigationViewItem> menuItems = [];


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

            // Set the initial NavigationView header
            MainNavigation.Header = "Create Policy";

            PopulateMenuItems();
        }


        /// <summary>
        /// Populate the dictionary with menu items for search purposes
        /// </summary>
        private void PopulateMenuItems()
        {
            foreach (NavigationViewItem item in MainNavigation.MenuItems.OfType<NavigationViewItem>())
            {
                menuItems[item.Content.ToString()!] = item;

                // If there are sub-items, add those as well
                if (item.MenuItems is not null && item.MenuItems.Count > 0)
                {
                    foreach (NavigationViewItem subItem in item.MenuItems.OfType<NavigationViewItem>())
                    {
                        menuItems[subItem.Content.ToString()!] = subItem;
                    }
                }
            }
        }

        /// <summary>
        /// Event handler for the AutoSuggestBox text change event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                string query = sender.Text.ToLower();

                // Filter menu items based on the search query
                List<string> suggestions = menuItems.Keys
                    .Where(name => name.Contains(query, System.StringComparison.OrdinalIgnoreCase))
                    .ToList();


                // Set the filtered items as suggestions in the AutoSuggestBox
                sender.ItemsSource = suggestions;
            }
        }

        /// <summary>
        /// Event handler for when a suggestion is chosen in the AutoSuggestBox
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void SearchBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
        {
            // Get the selected item's name and find the corresponding NavigationViewItem
            string? chosenItemName = args.SelectedItem?.ToString();
            if (chosenItemName is not null && menuItems.TryGetValue(chosenItemName, out NavigationViewItem? selectedItem))
            {
                // Select the item in the NavigationView
                MainNavigation.SelectedItem = selectedItem;

                if (selectedItem is not null)
                {
                    // Directly call NavigateToMenuItem with the selected item's tag
                    string? selectedTag = selectedItem.Tag?.ToString();

                    if (selectedTag is not null)
                    {
                        NavigateToMenuItem(selectedTag);
                    }
                }
            }
        }


        /// <summary>
        /// Event handler for main navigation menu selection change
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is NavigationViewItem selectedItem)
            {
                string selectedTag = selectedItem.Tag?.ToString()!;
                NavigateToMenuItem(selectedTag);
            }
        }


        /// <summary>
        /// Separate method to handle navigation based on the selected tag
        /// </summary>
        /// <param name="selectedTag"></param>
        private void NavigateToMenuItem(string selectedTag)
        {
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
                case "Deployment":
                    _ = ContentFrame.Navigate(typeof(Pages.Deployment));
                    break;
                case "EventLogsPolicyCreation":
                    _ = ContentFrame.Navigate(typeof(Pages.EventLogsPolicyCreation));
                    break;
                case "MDEAHPolicyCreation":
                    _ = ContentFrame.Navigate(typeof(Pages.MDEAHPolicyCreation));
                    break;
                case "AllowNewApps":
                    _ = ContentFrame.Navigate(typeof(Pages.AllowNewApps));
                    break;
                default:
                    break;
            }
        }


        /// <summary>
        /// Event handlers for the back button in the NavigationView
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavView_BackRequested(NavigationView sender, NavigationViewBackRequestedEventArgs args)
        {
            if (ContentFrame.CanGoBack)
            {

                // Don't go back if the nav pane is overlayed.
                /*
                if (MainNavigation.IsPaneOpen &&
                    (MainNavigation.DisplayMode == NavigationViewDisplayMode.Compact ||
                     MainNavigation.DisplayMode == NavigationViewDisplayMode.Minimal))
                */

                ContentFrame.GoBack();
            }
        }


        /// <summary>
        /// Set the NavigationView's header to the Navigation view item's content
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavigationView_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
        {
            if (MainNavigation.SelectedItem is NavigationViewItem item)
            {
                sender.Header = item.Content.ToString();
            }
        }


    }
}
