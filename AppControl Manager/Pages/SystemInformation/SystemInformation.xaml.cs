using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System.Linq;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace WDACConfig.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class SystemInformation : Page
    {
        public SystemInformation()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;


            // Navigate to the CreatePolicy page when the window is loaded
            _ = ContentFrame.Navigate(typeof(ViewCurrentPolicies));

            // Set the "CreatePolicy" item as selected in the NavigationView
            SystemInformationNavigation.SelectedItem = SystemInformationNavigation.MenuItems.OfType<NavigationViewItem>()
                .First(item => item.Tag.ToString() == "ViewCurrentPolicies");
        }


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
                    case "ViewCurrentPolicies":
                        _ = ContentFrame.Navigate(typeof(ViewCurrentPolicies));
                        break;
                    case "CodeIntegrityInfo":
                        _ = ContentFrame.Navigate(typeof(CodeIntegrityInfo));
                        break;
                    default:
                        break;
                }
            }
        }

    }
}
