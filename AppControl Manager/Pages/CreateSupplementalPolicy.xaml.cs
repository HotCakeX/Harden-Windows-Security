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
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class CreateSupplementalPolicy : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private CreateSupplementalPolicyVM ViewModel { get; } = ViewModelProvider.CreateSupplementalPolicyVM;
	private SidebarVM sideBarVM { get; } = ViewModelProvider.SidebarVM;

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

		sideBarVM.AssignActionPacks(
			actionPack1: (param => LightUp1(), GlobalVars.GetStr("FilesAndFoldersSupplementalPolicyLabel")),
			actionPack2: (param => LightUp2(), GlobalVars.GetStr("CertificatesSupplementalPolicyLabel")),
			actionPack3: (param => LightUp3(), GlobalVars.GetStr("ISGSupplementalPolicyLabel")),
			actionPack4: (param => LightUp4(), GlobalVars.GetStr("StrictKernelModeSupplementalPolicyLabel")),
			actionPack5: (param => LightUp5(), GlobalVars.GetStr("PFNSupplementalPolicyLabel")),
			actionPack6: (param => LightUp6(), GlobalVars.GetStr("CustomPatternBasedSupplementalPolicyLabel"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1()
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (FilesAndFoldersBrowseForBasePolicyButton.XamlRoot is not null)
		{
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
		}
		ViewModel.FilesAndFoldersBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp2()
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (CertificatesBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
		}
		ViewModel.CertificatesBasedBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp3()
	{
		if (ISGBrowseForBasePolicyButton.XamlRoot is not null)
		{
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
		}
		ViewModel.ISGBasedBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp4()
	{
		if (StrictKernelModeBrowseForBasePolicyButton.XamlRoot is not null)
		{
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicyButton);
		}
		ViewModel.StrictKernelModeBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp5()
	{
		if (PFNBrowseForBasePolicyButton.XamlRoot is not null)
		{
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicyButton);
		}
		ViewModel.PFNBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp6()
	{
		if (CustomPatternBasedFileRuleBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicyButton);
		}
		ViewModel.CustomPatternBasedFileRuleBasedBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}

	#endregion

	// Since using behaviors in XAML is not Native AOT compatible, we use event handlers.
	private async void OnBorderPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		await ShadowEnterAnimation.StartAsync((UIElement)sender);
	}
	private async void OnBorderPointerExited(object sender, PointerRoutedEventArgs e)
	{
		await ShadowExitAnimation.StartAsync((UIElement)sender);
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("CreateSupplementalPolicyPageTitle/Text");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy");

}
