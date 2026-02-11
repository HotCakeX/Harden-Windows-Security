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

using AppControlManager.SiPolicy;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class CreateSupplementalPolicy : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private CreateSupplementalPolicyVM ViewModel => ViewModelProvider.CreateSupplementalPolicyVM;
	private SidebarVM sideBarVM => ViewModelProvider.SidebarVM;

	internal CreateSupplementalPolicy()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.FilesAndFoldersBasePolicyLightAnimatedIconVisibility = visibility;
		ViewModel.CertificatesBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.ISGBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.StrictKernelModeBasePolicyLightAnimatedIconVisibility = visibility;
		ViewModel.PFNBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.CustomPatternBasedFileRuleBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.PolicyFileToMergeWithLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
			actionPack1: (LightUp1, GlobalVars.GetStr("FilesAndFoldersSupplementalPolicyLabel")),
			actionPack2: (LightUp2, GlobalVars.GetStr("CertificatesSupplementalPolicyLabel")),
			actionPack3: (LightUp3, GlobalVars.GetStr("ISGSupplementalPolicyLabel")),
			actionPack4: (LightUp4, GlobalVars.GetStr("StrictKernelModeSupplementalPolicyLabel")),
			actionPack5: (LightUp5, GlobalVars.GetStr("PFNSupplementalPolicyLabel")),
			actionPack6: (LightUp6, GlobalVars.GetStr("CustomPatternBasedSupplementalPolicyLabel")),
			actionPack7: (LightUp7, GlobalVars.GetStr("PolicyToAddNewRulesTo"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1(object? param)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (FilesAndFoldersBrowseForBasePolicyButton.XamlRoot is not null)
		{
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.FilesAndFoldersBasePolicy = policy;
		}
	}

	private void LightUp2(object? param)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (CertificatesBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.CertificatesBasedBasePolicy = policy;
		}
	}

	private void LightUp3(object? param)
	{
		if (ISGBrowseForBasePolicyButton.XamlRoot is not null)
		{
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.ISGBasedBasePolicy = policy;
		}
	}

	private void LightUp4(object? param)
	{
		if (StrictKernelModeBrowseForBasePolicyButton.XamlRoot is not null)
		{
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.StrictKernelModeBasePolicy = policy;
		}
	}

	private void LightUp5(object? param)
	{
		if (PFNBrowseForBasePolicyButton.XamlRoot is not null)
		{
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PFNBasePolicy = policy;
		}
	}

	private void LightUp6(object? param)
	{
		if (CustomPatternBasedFileRuleBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicyButton);
		}

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.CustomPatternBasedFileRuleBasedBasePolicy = policy;
		}
	}

	private void LightUp7(object? param)
	{
		SelectPolicyFileToAddRulesToButton_FlyOut.ShowAt(SelectPolicyFileToAddRulesToButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PolicyFileToMergeWith = policy;
		}
	}

	#endregion

	private async void OnBorderPointerEntered(object sender, PointerRoutedEventArgs e) =>
		await ShadowEnterAnimation.StartAsync((UIElement)sender);

	private async void OnBorderPointerExited(object sender, PointerRoutedEventArgs e) =>
		await ShadowExitAnimation.StartAsync((UIElement)sender);

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("CreateSupplementalPolicyPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy");

}
