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
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class MergePolicies : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private MergePoliciesVM ViewModel => ViewModelProvider.MergePoliciesVM;

	internal MergePolicies()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.MainMergePolicyLightAnimatedIconVisibility = visibility;
		ViewModel.OtherMergePoliciesLightAnimatedIconVisibility = visibility;
		ViewModel.AppIDTagConversionPolicyLightAnimatedIconVisibility = visibility;
		ViewModel.SigningScenarioRemovalPolicyLightAnimatedIconVisibility = visibility;

		ViewModelProvider.SidebarVM.AssignActionPacks(
			actionPack1: (LightUp1, GlobalVars.GetStr("MainPolicy")),
			actionPack2: (LightUp2, GlobalVars.GetStr("OtherPolicies")),
			actionPack3: (LightUp3, GlobalVars.GetStr("ConvertPoliciesToAppIDTaggingSettingsCard/Header")),
			actionPack4: (LightUp4, GlobalVars.GetStr("RemoveSigningScenarioFeatureSettingsCard/Header"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1(object? param)
	{
		MainPolicyForMergeBrowseButton_FlyOut.ShowAt(MainPolicyForMergeBrowseButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.MainPolicy = policy;
		}
	}

	private void LightUp2(object? param)
	{
		OtherPoliciesForMergeBrowseButton_FlyOut.ShowAt(OtherPoliciesForMergeBrowseButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.OtherPolicies.Add(policy);
		}
	}

	private void LightUp3(object? param)
	{
		AppIDTaggingConversionBrowseButton_FlyOut.ShowAt(AppIDTaggingConversionBrowseButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PoliciesToConvertToAppIDTagging.Add(policy);
		}
	}

	private void LightUp4(object? param)
	{
		SigningScenarioRemovalBrowseButton_FlyOut.ShowAt(SigningScenarioRemovalBrowseButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PoliciesForSigningScenarioRemoval.Add(policy);
		}
	}

	#endregion

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("MergePoliciesPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Merge-App-Control-Policies");

}
