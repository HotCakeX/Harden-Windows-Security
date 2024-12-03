using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Linq;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace AppControlManager.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class AllowNewApps : Page
    {
        // A static instance of the AllowNewApps class which will hold the single, shared instance of the page
        private static AllowNewApps? _instance;

        public AllowNewApps()
        {
            this.InitializeComponent();

            // Assign this instance to the static field
            _instance = this;

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Navigate to the AllowNewAppsStart page when the window is loaded
            _ = ContentFrame.Navigate(typeof(AllowNewAppsStart));

            // Set the "LocalFiles" item as selected in the NavigationView
            AllowNewAppsNavigation.SelectedItem = AllowNewAppsNavigation.MenuItems.OfType<NavigationViewItem>()
                .First(item => item.Tag.ToString() == "Start");

            DisableAllowNewAppsNavigationItem("LocalFiles");
            DisableAllowNewAppsNavigationItem("EventLogs");
        }

        // Public property to access the singleton instance from other classes
        public static AllowNewApps Instance => _instance ?? throw new InvalidOperationException("AllowNewApps is not initialized.");

        // Event handler for the navigation menu
        private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            // Check if the item is selected
            if (args.SelectedItem is NavigationViewItem selectedItem)
            {
                string? selectedTag = selectedItem.Tag?.ToString();

                // Navigate to the page based on the Tag
                switch (selectedTag)
                {
                    case "Start":
                        _ = ContentFrame.Navigate(typeof(AllowNewAppsStart));
                        break;
                    case "LocalFiles":
                        _ = ContentFrame.Navigate(typeof(AllowNewAppsLocalFilesDataGrid));
                        break;
                    case "EventLogs":
                        _ = ContentFrame.Navigate(typeof(AllowNewAppsEventLogsDataGrid));
                        break;
                    default:
                        break;
                }
            }
        }

        /// <summary>
        /// Disables a navigation item by its tag.
        /// </summary>
        /// <param name="tag">The tag of the navigation item to disable.</param>
        internal void DisableAllowNewAppsNavigationItem(string tag)
        {
            NavigationViewItem? item = AllowNewAppsNavigation.MenuItems
                .OfType<NavigationViewItem>()
                .FirstOrDefault(i => i.Tag?.ToString() == tag);

            if (item is not null)
            {
                item.IsEnabled = false;
            }
        }

        /// <summary>
        /// Enables a navigation item by its tag.
        /// </summary>
        /// <param name="tag">The tag of the navigation item to enable.</param>
        internal void EnableAllowNewAppsNavigationItem(string tag)
        {
            NavigationViewItem? item = AllowNewAppsNavigation.MenuItems
                .OfType<NavigationViewItem>()
                .FirstOrDefault(i => i.Tag?.ToString() == tag);

            if (item is not null)
            {
                item.IsEnabled = true;
            }
        }



        /// <summary>
        /// Updates the value and opacity of the LocalFiles InfoBadge.
        /// </summary>
        /// <param name="value">The new value for the InfoBadge. Use null to remove the value.</param>
        /// <param name="opacity">The new opacity for the InfoBadge (0.0 to 1.0).</param>
        public void UpdateLocalFilesInfoBadge(int? value, double opacity)
        {
            LocalFilesCountInfoBadge.Value = value ?? 0; // Default to 0 if value is null
            LocalFilesCountInfoBadge.Opacity = opacity;
        }

        /// <summary>
        /// Updates the value and opacity of the EventLogs InfoBadge.
        /// </summary>
        /// <param name="value">The new value for the InfoBadge. Use null to remove the value.</param>
        /// <param name="opacity">The new opacity for the InfoBadge (0.0 to 1.0).</param>
        public void UpdateEventLogsInfoBadge(int? value, double opacity)
        {
            EventLogsCountInfoBadge.Value = value ?? 0; // Default to 0 if value is null
            EventLogsCountInfoBadge.Opacity = opacity;
        }


    }
}
