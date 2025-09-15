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

using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a data grid for displaying event logs with functionalities for copying, sorting, filtering, and selecting
/// items.
/// </summary>
internal sealed partial class AllowNewAppsEventLogsDataGrid : Page
{

	private AllowNewAppsVM ViewModel { get; } = ViewModelProvider.AllowNewAppsVM;

	internal AllowNewAppsEventLogsDataGrid()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	/// <summary>
	/// Click event handler for copy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		// Grab the key out of the Tag
		string key = (string)((MenuFlyoutItem)sender).Tag;

		// Look up the mapping in the FileIdentity dictionary
		if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out var mapping))
		{
			ListViewHelper.CopyToClipboard<FileIdentity>(fi => mapping.Getter(fi)?.ToString(), FileIdentitiesListView);
		}
	}

}
