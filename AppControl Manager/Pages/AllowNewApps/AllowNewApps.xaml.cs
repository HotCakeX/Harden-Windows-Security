// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Linq;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for managing app permissions with navigation capabilities. It initializes the view model and
/// handles navigation events.
/// </summary>
public sealed partial class AllowNewApps : Page, Sidebar.IAnimatedIconsManager
{

#pragma warning disable CA1822
	internal AllowNewAppsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<AllowNewAppsVM>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the AllowNewApps page, sets up navigation caching, binds the data context, and navigates to the
	/// AllowNewAppsStart page.
	/// </summary>
	public AllowNewApps()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;

		// Navigate to the AllowNewAppsStart page when the window is loaded
		_ = ContentFrame.Navigate(typeof(AllowNewAppsStart));

		// Set the "LocalFiles" item as selected in the NavigationView
		AllowNewAppsNavigation.SelectedItem = AllowNewAppsNavigation.MenuItems.OfType<NavigationViewItem>()
			.First(item => string.Equals(item.Tag.ToString(), "Start", StringComparison.OrdinalIgnoreCase));
	}


	#region Augmentation Interface


	/// <summary>
	/// Called when the page is navigated to. Invokes the base navigation logic
	/// and updates the animated icons' visibility on the main window for the current content frame.
	/// </summary>
	/// <param name="e">The navigation event data.</param>
	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);
		MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}

	/// <summary>
	/// Called when the page is navigated away from. Invokes the base navigation logic
	/// and updates the animated icons' visibility on the main window for the current content frame.
	/// </summary>
	/// <param name="e">The navigation event data.</param>
	protected override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);
		MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}



	private string? unsignedBasePolicyPathFromSidebar;


	/// <summary>
	/// Sets the visibility of a button and updates related UI elements based on the provided parameters.
	/// </summary>
	/// <param name="visibility">Controls the visibility state of the buttons and icons in the UI.</param>
	/// <param name="unsignedBasePolicyPath">Stores the path for the unsigned policy from the sidebar into a local variable.</param>
	/// <param name="button1">Represents the first button whose visibility and content are updated based on the visibility state.</param>
	/// <param name="button2">Represents the second button, though its visibility is not directly modified in this context.</param>
	/// <param name="button3">Represents the third button, though its visibility is not directly modified in this context.</param>
	/// <param name="button4">Represents the fourth button, though its visibility is not directly modified in this context.</param>
	/// <param name="button5">Represents the fifth button, though its visibility is not directly modified in this context.</param>
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


	/// <summary>
	/// Handles changes in the navigation menu and navigates to different pages based on the selected item's tag.
	/// </summary>
	/// <param name="sender">Represents the navigation menu that triggered the selection change event.</param>
	/// <param name="args">Contains information about the selection change, including the newly selected item.</param>
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
}
