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
using AppControlManager.IntelGathering;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// AllowNewAppsStart is a page that manages the process of allowing new applications through policy management. It
/// handles user interactions for selecting policies, scanning directories, and creating supplemental policies.
/// </summary>
internal sealed partial class AllowNewAppsStart : Page, IAnimatedIconsManager
{

#pragma warning disable CA1822
	private AllowNewAppsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<AllowNewAppsVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private SidebarVM sideBarVM { get; } = App.AppHost.Services.GetRequiredService<SidebarVM>();
#pragma warning restore CA1822

	internal AllowNewAppsStart()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
		this.DataContext = ViewModel;

		BrowseForXMLPolicyButton_FlyOutPub = BrowseForXMLPolicyButton_FlyOut;
		BrowseForXMLPolicyButtonPub = BrowseForXMLPolicyButton;
	}

	#region Augmentation Interface

	// Exposing more elements to the main page of AllowNewApps since this is a sub-page managed by a 2nd NavigationView
	internal static Flyout? BrowseForXMLPolicyButton_FlyOutPub;
	internal static Button? BrowseForXMLPolicyButtonPub;

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.BrowseForXMLPolicyButtonLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
		(param => ViewModel.LightUp1(), "Allow New Apps Base Policy"),
		null, null, null, null);
	}

	#endregion

	/// <summary>
	/// Handles the selection change event for a ComboBox, updating the scan level based on the selected item.
	/// </summary>
	/// <param name="sender">Represents the source of the event, allowing access to the ComboBox that triggered the selection change.</param>
	/// <param name="e">Contains event data related to the selection change, providing information about the new selection.</param>
	private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedText = (string)comboBox.SelectedItem;

		ViewModel.scanLevel = Enum.Parse<ScanLevels>(selectedText);
	}
}
