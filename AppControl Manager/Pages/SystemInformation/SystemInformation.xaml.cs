using System;
using System.Linq;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

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
			.First(item => string.Equals(item.Tag.ToString(), "ViewCurrentPolicies", StringComparison.OrdinalIgnoreCase));
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
