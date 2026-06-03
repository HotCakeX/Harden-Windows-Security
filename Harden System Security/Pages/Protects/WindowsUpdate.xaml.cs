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

using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HardenSystemSecurity.Pages.Protects;

internal sealed partial class WindowsUpdate : Page, CommonCore.UI.IPageHeaderProvider
{
	private WindowsUpdateVM ViewModel => ViewModelProvider.WindowsUpdateVM;

	internal WindowsUpdate()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	/// <summary>
	/// OnNavigatedFrom indicates real page navigation, not transient Unloaded under TabView.
	/// We explicitly dispose the special controls that were prevented from auto-disposal.
	/// </summary>
	/// <param name="e"></param>
	protected override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);

		// Dispose all descendants that explicitly opted out of automatic disposal.
		ViewModelBase.DisposeExplicitOptInDescendants(SecurityMeasuresList);

		// Finally dispose the list control itself.
		SecurityMeasuresList.Dispose();
	}

	/// <summary>
	/// Hides the selected Windows updates.
	/// </summary>
	private async void HideSelectedUpdates_Click() =>
		await ViewModel.SetSelectedUpdatesHiddenState(WindowsUpdatesListView.SelectedItems, isHidden: true);

	/// <summary>
	/// Unhides the selected Windows updates.
	/// </summary>
	private async void UnhideSelectedUpdates_Click() =>
		await ViewModel.SetSelectedUpdatesHiddenState(WindowsUpdatesListView.SelectedItems, isHidden: false);

	/// <summary>
	/// Exports selected updates to JSON. If nothing is selected, all loaded updates are exported.
	/// </summary>
	private async void ExportUpdatesToJson_Click() =>
		await ViewModel.ExportUpdatesToJson(WindowsUpdatesListView.SelectedItems);

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("WindowsUpdatePageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Windows-Update");
}
