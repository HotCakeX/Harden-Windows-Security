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
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class CreateDenyPolicy : Page, IAnimatedIconsManager, CommonCore.UI.IPageHeaderProvider
{
	private CreateDenyPolicyVM ViewModel => ViewModelProvider.CreateDenyPolicyVM;

	internal CreateDenyPolicy()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.PolicyFileToMergeWithLightAnimatedIconVisibility = visibility;

		ViewModelProvider.SidebarVM.AssignActionPacks(
			actionPack1: (LightUp1, Atlas.GetStr("PolicyToAddNewRulesTo"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1(object? param)
	{
		SelectPolicyFileToAddRulesToButton_FlyOut.ShowAt(SelectPolicyFileToAddRulesToButton);

		if (param is PolicyFileRepresent policy)
		{
			ViewModel.PolicyFileToMergeWith = policy;

			ViewModel.OperationModeComboBoxSelectedIndex = 1;
		}
	}

	#endregion

	private void OnBorderPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		AnimateShadowBlur((FrameworkElement)sender, 20.0f);
	}

	private void OnBorderPointerExited(object sender, PointerRoutedEventArgs e)
	{
		AnimateShadowBlur((FrameworkElement)sender, 10.0f);
	}

	private void AnimateShadowBlur(FrameworkElement element, float toBlurRadius)
	{
		CommonCore.ToolKits.AttachedShadowBase? shadowBase = CommonCore.ToolKits.Effects.GetShadow(element);

		// Get the actual underlying GPU DropShadow to animate directly
		Microsoft.UI.Composition.DropShadow? dropShadow = shadowBase?.GetElementContext(element)?.Shadow;

		if (dropShadow != null)
		{
			Microsoft.UI.Composition.Compositor compositor = dropShadow.Compositor;
			Microsoft.UI.Composition.ScalarKeyFrameAnimation blurAnimation = compositor.CreateScalarKeyFrameAnimation();

			// Use the native Composition easing curve
			blurAnimation.InsertKeyFrame(1.0f, toBlurRadius, compositor.CreateCubicBezierEasingFunction(new System.Numerics.Vector2(0.1f, 0.9f), new System.Numerics.Vector2(0.2f, 1.0f)));
			blurAnimation.Duration = TimeSpan.FromMilliseconds(400);

			// Start the animation natively on the compositor
			dropShadow.StartAnimation("BlurRadius", blurAnimation);
		}
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("CreateDenyPolicyPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Deny-App-Control-Policy");
}
