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

using System.Linq;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinRT;

namespace AppControlManager.Pages;

internal sealed partial class SystemInformation : Page, CommonCore.UI.IPageHeaderProvider
{
	internal SystemInformation()
	{
		InitializeComponent();

		NavigationCacheMode = NavigationCacheMode.Disabled;

		if (Atlas.IsElevated)
		{
			// Navigate to a page when loaded
			_ = ContentFrame.Navigate(typeof(ViewCurrentPolicies));

			// Set the "ViewCurrentPolicies" item as selected in the NavigationView
			SystemInformationNavigation.SelectedItem = SystemInformationNavigation.MenuItems.OfType<NavigationViewItem>()
				.First(item => string.Equals(item.Tag.ToString(), "ViewCurrentPolicies", StringComparison.OrdinalIgnoreCase));
		}
		else
		{
			// Navigate to a page when loaded
			_ = ContentFrame.Navigate(typeof(ViewOnlinePolicies));

			// Set the "ViewOnlinePolicies" item as selected in the NavigationView
			SystemInformationNavigation.SelectedItem = SystemInformationNavigation.MenuItems.OfType<NavigationViewItem>()
				.First(item => string.Equals(item.Tag.ToString(), "ViewOnlinePolicies", StringComparison.OrdinalIgnoreCase));
		}
	}

	// Event handler for the navigation menu
	[DynamicWindowsRuntimeCast(typeof(NavigationViewItem))]
	private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
	{
		// Check if the item is selected and it's enabled (because when running unelevated, some pages are unavailable)
		if (args.SelectedItem is NavigationViewItem selectedItem && selectedItem.IsEnabled)
		{
			string? selectedTag = selectedItem.Tag?.ToString();

			// Navigate to the page based on the Tag
			switch (selectedTag)
			{
				case "ViewCurrentPolicies":
					_ = ContentFrame.Navigate(typeof(ViewCurrentPolicies));
					break;
				case "ViewOnlinePolicies":
					_ = ContentFrame.Navigate(typeof(ViewOnlinePolicies));
					break;
				case "CodeIntegrityInfo":
					_ = ContentFrame.Navigate(typeof(CodeIntegrityInfo));
					break;
				default:
					break;
			}
		}
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("SystemInformationPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information");
}
