using System;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class AllowNewApps : Page, Sidebar.IAnimatedIconsManager
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
			.First(item => string.Equals(item.Tag.ToString(), "Start", StringComparison.OrdinalIgnoreCase));

		DisableAllowNewAppsNavigationItem("LocalFiles");
		DisableAllowNewAppsNavigationItem("EventLogs");
	}


	#region Augmentation Interface


	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);

		MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}

	protected override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);

		MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}


	private string? unsignedBasePolicyPathFromSidebar;

	internal Frame ContentFramePub => ContentFrame;


	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3, Button button4, Button button5)
	{
		// Light up the local page's button icons
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButtonLightAnimatedIconPub.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;


		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Allow New Apps Base Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

		}

	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButton_FlyOutPub.ShowAt(AllowNewAppsStart.Instance.BrowseForXMLPolicyButtonPub);
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButton_SelectedBasePolicyTextBoxPub.Text = unsignedBasePolicyPathFromSidebar;
		AllowNewAppsStart.Instance.selectedXMLFilePath = unsignedBasePolicyPathFromSidebar;
	}


	#endregion


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

			// The same method that runs for the main Navigation in the MainWindow class must run here
			// Since this is a 2nd nested NavigationView and has different frame
			MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(ContentFrame);
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
