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

internal sealed partial class ComparePolicies : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private ComparePoliciesVM ViewModel => ViewModelProvider.ComparePoliciesVM;

	internal ComparePolicies()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface
	public void SetVisibility(Visibility visibility)
	{
		ViewModel.FirstPolicyLightAnimatedIconVisibility = visibility;
		ViewModel.SecondPolicyLightAnimatedIconVisibility = visibility;
		ViewModelProvider.SidebarVM.AssignActionPacks(
			actionPack1: (LightUp1, Atlas.GetStr("ComparePoliciesFirstPolicyLabel")),
			actionPack2: (LightUp2, Atlas.GetStr("ComparePoliciesSecondPolicyLabel"))
		);
	}
	private void LightUp1(object? param)
	{
		if (FirstPolicyBrowseButton.XamlRoot is not null)
		{
			FirstPolicyBrowseButton_FlyOut.ShowAt(FirstPolicyBrowseButton);
		}
		if (param is PolicyFileRepresent policy)
		{
			ViewModel.FirstPolicy = policy;
		}
	}
	private void LightUp2(object? param)
	{
		if (SecondPolicyBrowseButton.XamlRoot is not null)
		{
			SecondPolicyBrowseButton_FlyOut.ShowAt(SecondPolicyBrowseButton);
		}
		if (param is PolicyFileRepresent policy)
		{
			ViewModel.SecondPolicy = policy;
		}
	}
	#endregion

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("ComparePoliciesNavItem/ToolTipService/ToolTip");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Compare-Policies");
}
