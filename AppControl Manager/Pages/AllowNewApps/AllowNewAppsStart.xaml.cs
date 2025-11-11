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

using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
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

	private AllowNewAppsVM ViewModel { get; } = ViewModelProvider.AllowNewAppsVM;
	private SidebarVM sideBarVM { get; } = ViewModelProvider.SidebarVM;

	internal AllowNewAppsStart()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;

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
			actionPack1: (param => ViewModel.LightUp1(), GlobalVars.GetStr("AllowNewApps_SidebarButtonContent")));
	}

	#endregion
}
