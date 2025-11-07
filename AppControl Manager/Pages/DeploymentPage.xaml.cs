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
/// DeploymentPage manages the deployment of XML and CIP files, including signing and Intune integration. It handles
/// user interactions for file selection and deployment status updates.
/// </summary>
internal sealed partial class DeploymentPage : Page, IAnimatedIconsManager
{
	private DeploymentVM ViewModel { get; } = ViewModelProvider.DeploymentVM;
	private SidebarVM sideBarVM { get; } = ViewModelProvider.SidebarVM;

	internal DeploymentPage()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = this;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.UnsignedXMLFilesLightAnimatedIconVisibility = visibility;
		ViewModel.SignedXMLFilesLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
			actionPack1: (param => LightUp1(), GlobalVars.GetStr("DeployUnsignedPolicy")),
			actionPack2: (param => LightUp2(), GlobalVars.GetStr("DeploySignedPolicy")));
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1()
	{
		if (!string.IsNullOrWhiteSpace(MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic))
		{
			ViewModel.XMLFiles.Add(MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic);

			BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
		}
	}

	private void LightUp2()
	{
		if (!string.IsNullOrWhiteSpace(MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic))
		{
			ViewModel.SignedXMLFiles.Add(MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic);

			BrowseForSignedXMLPolicyFilesButton_Flyout.ShowAt(BrowseForSignedXMLPolicyFilesButton);
		}
	}

	#endregion

}
