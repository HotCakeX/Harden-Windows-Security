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
/// Configures policy rules and manages UI interactions for policy templates. Initializes components, handles file
/// selection, and updates settings dynamically.
/// </summary>
internal sealed partial class ConfigurePolicyRuleOptions : Page, IAnimatedIconsManager
{
	private ConfigurePolicyRuleOptionsVM ViewModel { get; } = ViewModelProvider.ConfigurePolicyRuleOptionsVM;
	private SidebarVM sideBarVM { get; } = ViewModelProvider.SidebarVM;

	internal ConfigurePolicyRuleOptions()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.BrowseForXMLPolicyButtonLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
			actionPack1: (param => LightUp1(), GlobalVars.GetStr("ConfigurePolicyRuleOptions_ButtonContent")));
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private async void LightUp1()
	{
		try
		{
			PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
			ViewModel.SelectedFilePath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;

			await ViewModel.LoadPolicyOptionsFromXML();
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
	}

	#endregion

}
