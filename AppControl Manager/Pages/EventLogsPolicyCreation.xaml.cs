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
using AppControlManager.SiPolicy;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class EventLogsPolicyCreation : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private EventLogsPolicyCreationVM ViewModel => ViewModelProvider.EventLogsPolicyCreationVM;
	private SidebarVM sideBarVM => ViewModelProvider.SidebarVM;

	internal EventLogsPolicyCreation()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icon
		ViewModel.LightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
			actionPack1: (LightUp1, GlobalVars.GetStr("AddToPolicySegmentedItem/Content")),
			actionPack2: (LightUp2, GlobalVars.GetStr("BasePolicyFileSegmentedItem/Content"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1(object? param)
	{
		// Show the first flyout for the Split button
		MainSplitButton.Flyout.ShowAt(MainSplitButton);

		// Switch to the correct index in the Segmented control
		ViewModel.SelectedCreationMethod = 0;

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PolicyToAddLogsTo = policy;
		}

		// XAML Root problem
		// PolicyToAddLogsToButton_FlyOut.ShowAt(PolicyToAddLogsToButton);
	}

	private void LightUp2(object? param)
	{
		// Show the first flyout for the Split button
		MainSplitButton.Flyout.ShowAt(MainSplitButton);

		// Switch to the correct index in the Segmented control
		ViewModel.SelectedCreationMethod = 1;

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.BasePolicyXMLFile = policy;
		}

		// XAML Root problem
		// BasePolicyButton_FlyOut.ShowAt(BasePolicyButton);
	}

	#endregion

	/// <summary>
	/// Click event handler for copy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		// Attempt to retrieve the property mapping using the Tag as the key.
		if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue((string)((MenuFlyoutItem)sender).Tag, out var mapping))
		{
			ListViewHelper.CopyToClipboard<FileIdentity>(fi => mapping.Getter(fi)?.ToString(), FileIdentitiesListView);
		}
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("EventLogsPolicyCreationPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-Event-Logs");

}
