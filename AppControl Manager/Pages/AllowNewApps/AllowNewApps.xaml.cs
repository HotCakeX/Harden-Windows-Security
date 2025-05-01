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
using AppControlManager.WindowComponents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for managing app permissions with navigation capabilities. It initializes the view model and
/// handles navigation events.
/// </summary>
internal sealed partial class AllowNewApps : Page, IAnimatedIconsManager
{

#pragma warning disable CA1822
	private AllowNewAppsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<AllowNewAppsVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private SidebarVM sideBarVM { get; } = App.AppHost.Services.GetRequiredService<SidebarVM>();
	private NavigationService nav { get; } = App.AppHost.Services.GetRequiredService<NavigationService>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the AllowNewApps page, sets up navigation caching, binds the data context, and navigates to the
	/// AllowNewAppsStart page.
	/// </summary>
	internal AllowNewApps()
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
		nav.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}

	/// <summary>
	/// Called when the page is navigated away from. Invokes the base navigation logic
	/// and updates the animated icons' visibility on the main window for the current content frame.
	/// </summary>
	/// <param name="e">The navigation event data.</param>
	protected override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);
		nav.AffectPagesAnimatedIconsVisibilities(ContentFrame);
	}

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButtonLightAnimatedIconPub.Visibility = visibility;

		sideBarVM.AssignActionPacks(
		(param => LightUp1(), "Allow New Apps Base Policy"),
		null, null, null, null);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private static void LightUp1()
	{
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButton_FlyOutPub.ShowAt(AllowNewAppsStart.Instance.BrowseForXMLPolicyButtonPub);
		AllowNewAppsStart.Instance.BrowseForXMLPolicyButton_SelectedBasePolicyTextBoxPub.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		AllowNewAppsStart.Instance.selectedXMLFilePath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
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
			nav.AffectPagesAnimatedIconsVisibilities(ContentFrame);
		}
	}
}
