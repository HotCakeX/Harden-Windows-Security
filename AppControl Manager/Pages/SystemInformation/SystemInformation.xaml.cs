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

namespace AppControlManager.Pages;

internal sealed partial class SystemInformation : Page, CommonCore.UI.IPageHeaderProvider
{
	private AppSettings.Main AppSettings => App.Settings;

	internal SystemInformation()
	{
		InitializeComponent();

		NavigationCacheMode = NavigationCacheMode.Disabled;

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

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("SystemInformationPageTitle/Text");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information");
}
